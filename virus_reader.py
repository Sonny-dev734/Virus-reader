#!/usr/bin/env python3
"""A small, non-destructive local file risk scanner.

This utility identifies files that deserve a closer look. It is not a replacement
for a full antivirus product because it does not use malware signatures or remove
files.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import time
from collections import Counter
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from ctypes import wintypes

SUSPICIOUS_EXTENSIONS = {
    ".bat", ".cmd", ".com", ".exe", ".js", ".jse", ".msi", ".ps1",
    ".scr", ".vbe", ".vbs", ".wsf",
}
TEXT_SCAN_EXTENSIONS = {
    ".bat", ".cmd", ".js", ".jse", ".ps1", ".py", ".sh", ".vbe",
    ".vbs", ".viwsf",
}
DOUBLE_EXTENSION_SUFFIXES = {".bat", ".cmd", ".com", ".exe", ".js", ".scr", ".vbs"}
MAX_HASH_SIZE = 100 * 1024 * 1024  # 100 MiB
MAX_CONTENT_SCAN_SIZE = 2 * 1024 * 1024  # 2 MiB
DEFAULT_URL_BLACKLIST = Path(__file__).with_name("url_blacklist.txt")
DEFAULT_THREAT_INTEL_CACHE = Path(__file__).with_name("threat_intel_cache.json")
DEFAULT_HUB_PAGE = Path(__file__).with_name("hub.html")
DEFAULT_AUTH_RESULT = Path(__file__).with_name("authentication_analysis_result.json")
URLHAUS_HOSTFILE_URL = "https://urlhaus.abuse.ch/downloads/hostfile/"
URL_PATTERN = re.compile(r"https?://[^\s\"'<>()]+", re.IGNORECASE)
CONTENT_INDICATORS = {
    "PowerShell encoded command": re.compile(r"(?:-enc|-encodedcommand)\s+[a-z0-9+/=]{16,}", re.IGNORECASE),
    "PowerShell download cradle": re.compile(
        r"(?:invoke-webrequest|downloadstring|downloadfile|start-bitstransfer)", re.IGNORECASE
    ),
    "PowerShell expression execution": re.compile(r"(?:\biex\b|invoke-expression)", re.IGNORECASE),
    "Command shell execution": re.compile(r"(?:cmd\.exe\s*/c|powershell(?:\.exe)?\s+-)", re.IGNORECASE),
    "Script created from encoded content": re.compile(
        r"(?:frombase64string|base64_decode|certutil\s+-decode)", re.IGNORECASE
    ),
    "Potential remote payload URL": URL_PATTERN,
    "Input-capture API reference": re.compile(
        r"(?:getasynckeystate|setwindowshookex|pynput|keyboard\.(?:hook|on_press))", re.IGNORECASE
    ),
    "Startup persistence reference": re.compile(
        r"(?:currentversion\\run(?:once)?|startup\\|reg(?:\.exe)?\s+add)", re.IGNORECASE
    ),
    "Scheduled-task persistence": re.compile(r"schtasks(?:\.exe)?\s+/create", re.IGNORECASE),
    "Ransomware recovery-inhibition command": re.compile(
        r"(?:vssadmin(?:\.exe)?\s+delete|wbadmin(?:\.exe)?\s+delete|bcdedit(?:\.exe)?.*recoveryenabled)",
        re.IGNORECASE,
    ),
    "Cryptomining indicator": re.compile(r"(?:stratum\+tcp|xmrig|coinhive)", re.IGNORECASE),
}

THREAT_CATEGORY_INDICATORS = {
    "Malware": (*CONTENT_INDICATORS, "URL matched local blacklist"),
    "Trojan / dropper": (
        "Potential remote payload URL", "PowerShell download cradle", "double_extensions",
    ),
    "RAT / backdoor": (
        "Potential remote payload URL", "PowerShell download cradle", "Command shell execution",
        "Startup persistence reference", "Scheduled-task persistence", "URL matched local blacklist",
    ),
    "Spyware / keylogger": ("Input-capture API reference",),
    "Ransomware / wiper": ("Ransomware recovery-inhibition command",),
    "Cryptojacking": ("Cryptomining indicator",),
    "Fileless malware": (
        "PowerShell encoded command", "PowerShell expression execution", "Script created from encoded content",
    ),
    "Browser hijacking": ("Startup persistence reference",),
}
SPECIALIST_CATEGORIES = {
    "Memory-resident malware": "requires memory forensics or endpoint detection",
    "Worm": "requires network and host-to-host behavior monitoring",
    "Malvertising": "requires browser, DNS, and web-filter telemetry",
    "Rootkit": "requires kernel-integrity and rootkit-specific inspection",
    "Kernel access / control": "requires kernel-driver and integrity inspection",
    "RAM scraper": "requires process-memory inspection",
    "DDoS attack": "requires live network-flow monitoring",
    "Rogue security software": "requires application reputation and behavior analysis",
    "Brute-force attack": "requires authentication event-log analysis",
    "Phishing communications": "requires mail, browser, and URL-reputation analysis",
}


@dataclass
class Finding:
    path: Path
    reasons: list[str]
    size: int
    severity: str
    sha256: str | None = None


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest for a file."""
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_url_blacklist(path: Path | None) -> set[str]:
    """Load a local domain blacklist; comments and blank lines are ignored."""
    if path is None or not path.is_file():
        return set()
    try:
        with path.open(encoding="utf-8") as blacklist_file:
            return {
                line.strip().lower().lstrip(".")
                for line in blacklist_file
                if line.strip() and not line.lstrip().startswith("#")
            }
    except OSError:
        return set()


def parse_host_feed(content: str) -> set[str]:
    """Parse hostname entries from a trusted plain-text threat feed."""
    hosts = set()
    for line in content.splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        fields = entry.split()
        host = fields[1] if len(fields) > 1 and re.fullmatch(r"\d+(?:\.\d+){3}", fields[0]) else fields[0]
        host = host.lower().rstrip(".")
        if re.fullmatch(r"[a-z0-9.-]+", host) and "." in host:
            hosts.add(host)
    return hosts


def load_threat_intel_cache(path: Path) -> set[str]:
    """Load previously fetched threat-intelligence hosts for offline scanning."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        hosts = payload.get("hosts", [])
    except (OSError, json.JSONDecodeError, AttributeError):
        return set()
    return {host for host in hosts if isinstance(host, str)}


def load_online_threat_intel(cache_path: Path, offline: bool) -> tuple[set[str], str]:
    """Fetch a public malware-host feed or use its local cache when offline."""
    cached_hosts = load_threat_intel_cache(cache_path)
    if offline:
        return cached_hosts, "offline cache" if cached_hosts else "offline cache unavailable"
    try:
        request = Request(URLHAUS_HOSTFILE_URL, headers={"User-Agent": "LocalFileRiskScanner/1.0"})
        with urlopen(request, timeout=15) as response:
            hosts = parse_host_feed(response.read().decode("utf-8", errors="replace"))
        if not hosts:
            raise ValueError("feed contained no hostnames")
        cache_path.write_text(
            json.dumps({"fetched_at": int(time.time()), "source": URLHAUS_HOSTFILE_URL, "hosts": sorted(hosts)}),
            encoding="utf-8",
        )
        return hosts, "online feed refreshed"
    except (OSError, ValueError):
        return cached_hosts, "online feed unavailable; using cache" if cached_hosts else "online feed and cache unavailable"


def is_blacklisted_host(host: str, blacklist: set[str]) -> bool:
    """Match an exact blacklisted domain or one of its subdomains."""
    host = host.lower().rstrip(".")
    return any(host == domain or host.endswith(f".{domain}") for domain in blacklist)


def inspect_content(path: Path, size: int, url_blacklist: set[str]) -> list[str]:
    """Look for transparent, static indicators in small text-like files."""
    if size > MAX_CONTENT_SCAN_SIZE:
        return []
    try:
        content = path.read_bytes().decode("utf-8", errors="ignore")
    except (OSError, PermissionError):
        return []
    matches = [label for label, pattern in CONTENT_INDICATORS.items() if pattern.search(content)]
    if url_blacklist:
        hosts = {
            urlparse(url.rstrip(".,;:!?")).hostname
            for url in URL_PATTERN.findall(content)
        }
        if any(host and is_blacklisted_host(host, url_blacklist) for host in hosts):
            matches.append("URL matched local blacklist")
    return matches


def assess_severity(reasons: list[str]) -> str:
    """Assign a conservative review priority, not a malware verdict."""
    content_matches = sum(reason.startswith("Content indicator:") for reason in reasons)
    if content_matches >= 2 or (
        content_matches and "Potentially misleading double extension" in reasons
    ):
        return "HIGH — review promptly"
    if content_matches or "Potentially misleading double extension" in reasons:
        return "MEDIUM — review"
    return "LOW — file type review"


def inspect_file(
    path: Path, hash_files: bool, deep_scan: bool, url_blacklist: set[str]
) -> Finding | None:
    """Assess a file using simple, transparent heuristics."""
    try:
        size = path.stat().st_size
    except OSError:
        return None

    suffixes = [suffix.lower() for suffix in path.suffixes]
    reasons = []

    if path.suffix.lower() in SUSPICIOUS_EXTENSIONS:
        reasons.append(f"Executable or script file ({path.suffix.lower()})")

    if len(suffixes) >= 2 and suffixes[-1] in DOUBLE_EXTENSION_SUFFIXES:
        reasons.append("Potentially misleading double extension")

    if path.name.startswith(".") and path.suffix.lower() in SUSPICIOUS_EXTENSIONS:
        reasons.append("Hidden executable or script file")

    if deep_scan and path.suffix.lower() in TEXT_SCAN_EXTENSIONS and path.resolve() != Path(__file__).resolve():
        reasons.extend(
            f"Content indicator: {match}"
            for match in inspect_content(path, size, url_blacklist)
        )

    if not reasons:
        return None

    file_hash = None
    if hash_files and size <= MAX_HASH_SIZE:
        try:
            file_hash = sha256_file(path)
        except (OSError, PermissionError):
            reasons.append("Could not calculate SHA-256 hash")
    elif hash_files:
        reasons.append("SHA-256 skipped: file is larger than 100 MiB")

    return Finding(path, reasons, size, assess_severity(reasons), file_hash)


def format_size(size: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TiB"


def scan(
    folder: Path, hash_files: bool, deep_scan: bool, url_blacklist: set[str]
) -> tuple[list[Finding], int, int, Counter[str]]:
    """Recursively scan a folder without modifying any content."""
    findings = []
    files_checked = 0
    files_skipped = 0
    diagnostics: Counter[str] = Counter()

    for root, directories, files in os.walk(folder, onerror=lambda _: None):
        directories[:] = [directory for directory in directories if not Path(root, directory).is_symlink()]
        for name in files:
            path = Path(root, name)
            if path.is_symlink():
                files_skipped += 1
                continue
            files_checked += 1
            finding = inspect_file(path, hash_files, deep_scan, url_blacklist)
            if finding:
                findings.append(finding)
                for reason in finding.reasons:
                    if reason.startswith("Executable or script file"):
                        diagnostics["risky_file_types"] += 1
                    elif reason == "Potentially misleading double extension":
                        diagnostics["double_extensions"] += 1
                    elif reason == "Hidden executable or script file":
                        diagnostics["hidden_scripts"] += 1
                    elif reason.startswith("Content indicator:"):
                        diagnostics[reason[len("Content indicator: "):]] += 1

    return findings, files_checked, files_skipped, diagnostics


def print_check(label: str, count: int, enabled: bool = True) -> None:
    """Print one readable diagnostic status without calling a file safe or malicious."""
    if not enabled:
        print(f"  [—] {label}: not checked")
    elif count:
        suffix = "match" if count == 1 else "matches"
        print(f"  [!] {label}: {count} {suffix} detected")
    else:
        print(f"  [✓] {label}: none detected")


def print_assessment(label: str, result: str) -> None:
    """Print a high-level threat category without overstating scanner coverage."""
    print(f"  {label:<20} {result}")


def indicator_summary(count: int, description: str) -> str:
    """Describe a category as a scanner observation rather than a verdict."""
    if not count:
        return f"no {description} indicators detected"
    suffix = "indicator" if count == 1 else "indicators"
    return f"{count} {description} {suffix} detected"


def category_match_count(category: str, diagnostics: Counter[str]) -> int:
    """Count static indicators relevant to one high-level threat category."""
    labels = THREAT_CATEGORY_INDICATORS[category]
    return sum(diagnostics[label] for label in labels)


def print_threat_coverage(
    diagnostics: Counter[str], deep_scan: bool, memory_forensics_ran: bool,
    process_memory_inspection_ran: bool, network_monitor_ran: bool,
    auth_log_analysis_ran: bool | None,
) -> None:
    """Report observed indicators and clearly state coverage boundaries."""
    print("THREAT-TYPE QUICK RUNDOWN")
    for category in THREAT_CATEGORY_INDICATORS:
        if not deep_scan:
            result = "not assessed — run with --deep"
        else:
            count = category_match_count(category, diagnostics)
            result = indicator_summary(count, "relevant static")
        print_assessment(f"{category}:", result)

    for category, requirement in SPECIALIST_CATEGORIES.items():
        if category == "Memory-resident malware" and memory_forensics_ran:
            result = "live process-memory triage completed — see MEMORY FORENSICS results"
        elif category == "RAM scraper" and process_memory_inspection_ran:
            result = "process-memory region inspection completed — see MEMORY FORENSICS results"
        elif category == "Worm" and network_monitor_ran:
            result = "host-to-host connection monitoring completed — see NETWORK MONITOR results"
        elif category == "Brute-force attack" and auth_log_analysis_ran:
            result = "authentication event-log analysis completed — see AUTHENTICATION ANALYSIS results"
        elif category == "Brute-force attack" and auth_log_analysis_ran is None:
            result = "analysis unavailable — Security event-log access requires Administrator permission"
        else:
            result = f"not assessed — {requirement}"
        print_assessment(f"{category}:", result)


def run_powershell(command: str) -> object | None:
    """Run a read-only Windows security query and parse its JSON response."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode or not result.stdout.strip():
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def print_windows_security_diagnostics(run_quick_scan: bool) -> None:
    """Report evidence from Microsoft Defender and Windows Firewall on Windows."""
    if platform.system() != "Windows":
        print("OS SECURITY CHECK: unavailable — Microsoft Defender integration is Windows-only.")
        return

    if run_quick_scan:
        print("OS SECURITY CHECK: launching Microsoft Defender quick scan...")
        try:
            subprocess.Popen(
                [
                    "powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command",
                    "Start-MpScan -ScanType QuickScan",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            print("  [i] Defender quick scan launched; it continues in the background")
        except OSError:
            print("  [!] Defender quick scan could not start")

    status = run_powershell(
        "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,"
        "RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,"
        "AntivirusSignatureLastUpdated,QuickScanAge,FullScanAge | ConvertTo-Json -Compress"
    )
    firewall = run_powershell(
        "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress"
    )
    detections = run_powershell(
        "@(Get-MpThreatDetection | Select-Object -First 20 ThreatName,InitialDetectionTime,ActionSuccess) | ConvertTo-Json -Compress"
    )

    print("OS SECURITY CHECK: Microsoft Defender and Windows Firewall")
    if isinstance(status, dict):
        print(f"  [i] Defender service: {'enabled' if status.get('AMServiceEnabled') else 'disabled'}")
        print(f"  [i] Antivirus engine: {'enabled' if status.get('AntivirusEnabled') else 'disabled'}")
        print(f"  [i] Real-time protection: {'enabled' if status.get('RealTimeProtectionEnabled') else 'disabled'}")
        print(f"  [i] Behavior monitoring: {'enabled' if status.get('BehaviorMonitorEnabled') else 'disabled'}")
        print(f"  [i] Download protection: {'enabled' if status.get('IoavProtectionEnabled') else 'disabled'}")
        print(f"  [i] Signature updated: {status.get('AntivirusSignatureLastUpdated', 'unknown')}")
        print(f"  [i] Quick scan age: {status.get('QuickScanAge', 'unknown')} day(s)")
    else:
        print("  [!] Microsoft Defender status could not be read")

    if isinstance(firewall, dict):
        firewall = [firewall]
    if isinstance(firewall, list):
        for profile in firewall:
            state = "enabled" if profile.get("Enabled") else "disabled"
            print(f"  [i] Firewall {profile.get('Name', 'unknown')} profile: {state}")
    else:
        print("  [!] Windows Firewall status could not be read")

    if detections is None:
        print("  [—] Defender detection history: unavailable (access may be restricted)")
    else:
        detection_count = len(detections) if isinstance(detections, list) else 1
        print(f"  [i] Defender detection-history entries returned: {detection_count}")
    print("  [i] This is evidence of current protection status, not proof that the OS is infection-free.")


def print_windows_system_audit() -> None:
    """Inspect Windows security-relevant system surfaces using built-in commands."""
    if platform.system() != "Windows":
        print("SYSTEM AUDIT: unavailable — this audit currently supports Windows only.")
        return

    checks = (
        (
            "Startup entries",
            "@(Get-CimInstance Win32_StartupCommand -ErrorAction Stop).Count | ConvertTo-Json -Compress",
            "Review unknown persistence entries with Task Manager or Autoruns.",
        ),
        (
            "Enabled scheduled tasks",
            "@(Get-ScheduledTask -ErrorAction Stop | Where-Object State -ne 'Disabled').Count | ConvertTo-Json -Compress",
            "Scheduled tasks can provide persistence; a count alone is not malicious.",
        ),
        (
            "Running services",
            "@(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object State -eq 'Running').Count | ConvertTo-Json -Compress",
            "Services are normal; investigate unknown service names and paths.",
        ),
        (
            "Running kernel drivers",
            "@(Get-CimInstance Win32_SystemDriver -ErrorAction Stop | Where-Object State -eq 'Running').Count | ConvertTo-Json -Compress",
            "A count is an inventory signal, not evidence of a rootkit.",
        ),
        (
            "Listening network ports",
            "@(Get-NetTCPConnection -State Listen -ErrorAction Stop).Count | ConvertTo-Json -Compress",
            "Listeners are normal for some apps; review unexpected public-facing services.",
        ),
        (
            "Defender exclusion paths",
            "@((Get-MpPreference -ErrorAction Stop).ExclusionPath).Count | ConvertTo-Json -Compress",
            "Unexpected exclusions can weaken antivirus coverage.",
        ),
        (
            "Failed logons, last 24 hours",
            "@((Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-24)} -ErrorAction Stop)).Count | ConvertTo-Json -Compress",
            "Requires Security event-log access; high counts can indicate brute-force attempts.",
        ),
    )
    uac = run_powershell(
        "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' "
        "-ErrorAction Stop | Select-Object EnableLUA,ConsentPromptBehaviorAdmin | ConvertTo-Json -Compress"
    )

    print("SYSTEM AUDIT: built-in Windows telemetry")
    for label, command, note in checks:
        value = run_powershell(command)
        if isinstance(value, int):
            print(f"  [i] {label}: {value}")
        else:
            print(f"  [—] {label}: unavailable (run the terminal as Administrator if access is denied)")
        print(f"      {note}")

    if isinstance(uac, dict):
        uac_state = "enabled" if uac.get("EnableLUA") else "disabled"
        print(f"  [i] User Account Control: {uac_state}")
    else:
        print("  [—] User Account Control: unavailable")
    print("  [i] This audit is observational: it does not alter services, drivers, firewall rules, or files.")


def print_windows_authentication_analysis(
    hours: int, result_path: Path | None = None
) -> bool | None:
    """Summarize Windows authentication failures without changing security logs."""
    if platform.system() != "Windows":
        print("AUTHENTICATION ANALYSIS: unavailable — Windows Security event logs are Windows-only.")
        return None
    report = run_powershell(
        "$events = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; "
        f"StartTime=(Get-Date).AddHours(-{hours})}} -MaxEvents 5000 -ErrorAction Stop); "
        "$records = foreach ($event in $events) { "
        "$xml = [xml]$event.ToXml(); $data = @{}; "
        "foreach ($node in $xml.Event.EventData.Data) { $data[$node.Name] = $node.'#text' }; "
        "[PSCustomObject]@{ Account = $data['TargetUserName']; SourceIp = $data['IpAddress'] } }; "
        "$remote = @($records | Where-Object { $_.SourceIp -and $_.SourceIp -notin @('-', '127.0.0.1', '::1') }); "
        "[PSCustomObject]@{ FailedLogons = $events.Count; RemoteFailedLogons = $remote.Count; "
        "TopSources = @($remote | Group-Object SourceIp | Sort-Object Count -Descending | Select-Object -First 10 @{Name='Source';Expression={$_.Name}},Count); "
        "TopAccounts = @($records | Where-Object { $_.Account -and $_.Account -ne '-' } | Group-Object Account | Sort-Object Count -Descending | Select-Object -First 10 @{Name='Account';Expression={$_.Name}},Count) } | "
        "ConvertTo-Json -Depth 3 -Compress"
    )
    print(f"AUTHENTICATION ANALYSIS: read-only failed-logon review (last {hours} hour(s))")
    if not isinstance(report, dict):
        print("  [—] Security event-log access unavailable (run the terminal as Administrator if access is denied)")
        return None
    if result_path is not None:
        try:
            result_path.write_text(
                json.dumps({"hours": hours, "report": report}), encoding="utf-8"
            )
        except OSError:
            print("  [—] Could not save elevated authentication results for the original terminal")
    print(f"  [i] Failed logons (Event ID 4625): {report.get('FailedLogons', 'unknown')}")
    print(f"  [i] Failures with remote source IPs: {report.get('RemoteFailedLogons', 'unknown')}")
    for source in report.get("TopSources", []):
        print(f"  [!] Review source IP: {source.get('Source', 'unknown')} ({source.get('Count', '?')} failures)")
    for account in report.get("TopAccounts", []):
        print(f"  [i] Target account: {account.get('Account', 'unknown')} ({account.get('Count', '?')} failures)")
    print("  [i] Counts are investigation signals, not proof of a brute-force attack.")
    return True


def print_saved_authentication_results(result_path: Path) -> bool:
    """Display a completed elevated authentication analysis in the original terminal."""
    try:
        payload = json.loads(result_path.read_text(encoding="utf-8"))
        report = payload["report"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError):
        print("  [—] Elevated authentication analysis finished without a readable result")
        return False
    print("AUTHENTICATION ANALYSIS: elevated results")
    print(f"  [i] Failed logons (Event ID 4625): {report.get('FailedLogons', 'unknown')}")
    print(f"  [i] Failures with remote source IPs: {report.get('RemoteFailedLogons', 'unknown')}")
    for source in report.get("TopSources", []):
        print(f"  [!] Review source IP: {source.get('Source', 'unknown')} ({source.get('Count', '?')} failures)")
    for account in report.get("TopAccounts", []):
        print(f"  [i] Target account: {account.get('Account', 'unknown')} ({account.get('Count', '?')} failures)")
    print("  [i] Counts are investigation signals, not proof of a brute-force attack.")
    return True


def print_windows_network_monitor() -> bool:
    """Inventory active Windows connections and their owning processes without altering traffic."""
    if platform.system() != "Windows":
        print("NETWORK MONITOR: unavailable — host-to-host monitoring currently supports Windows only.")
        return False
    connections = run_powershell(
        "@(Get-NetTCPConnection -State Established -ErrorAction Stop | "
        "Where-Object RemoteAddress -notin @('127.0.0.1','::1','0.0.0.0','::') | "
        "Select-Object OwningProcess,RemoteAddress,RemotePort) | ConvertTo-Json -Compress"
    )
    if isinstance(connections, dict):
        connections = [connections]
    if not isinstance(connections, list):
        print("NETWORK MONITOR: unavailable (run the terminal as Administrator if access is denied)")
        return False
    remote_hosts = {connection.get("RemoteAddress") for connection in connections if isinstance(connection, dict)}
    process_ids = {connection.get("OwningProcess") for connection in connections if isinstance(connection, dict)}
    print("NETWORK MONITOR: read-only host-to-host connection snapshot")
    print(f"  [i] Established remote TCP connections: {len(connections)}")
    print(f"  [i] Unique remote hosts: {len(remote_hosts)} | Owning processes: {len(process_ids)}")
    for connection in connections[:10]:
        print(
            f"  [i] PID {connection.get('OwningProcess', '?')} -> "
            f"{connection.get('RemoteAddress', 'unknown')}:{connection.get('RemotePort', '?')}"
        )
    print("  [i] This is a point-in-time inventory; it does not capture packets or prove host-to-host propagation.")
    return True


def inspect_windows_process_memory() -> dict[str, object] | None:
    """Inspect process virtual-memory metadata without reading process contents."""
    if platform.system() != "Windows":
        return None

    class MemoryBasicInformation(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wintypes.DWORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD),
        ]

    process_query_limited_information = 0x1000
    process_vm_read = 0x0010
    mem_commit = 0x1000
    mem_private = 0x20000
    page_execute = 0x10
    page_execute_read = 0x20
    page_execute_readwrite = 0x40
    page_execute_writecopy = 0x80
    executable_protections = {
        page_execute, page_execute_read, page_execute_readwrite, page_execute_writecopy,
    }
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.VirtualQueryEx.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(MemoryBasicInformation), ctypes.c_size_t,
    ]
    kernel32.VirtualQueryEx.restype = ctypes.c_size_t
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    private_executable_region_count = 0
    writable_executable_regions = []
    processes_inspected = 0
    processes_restricted = 0
    for process in run_powershell(
        "@(Get-Process | Select-Object ProcessName,Id) | ConvertTo-Json -Compress"
    ) or []:
        if not isinstance(process, dict):
            continue
        process_id = process.get("Id")
        if not isinstance(process_id, int):
            continue
        handle = kernel32.OpenProcess(
            process_query_limited_information | process_vm_read, False, process_id
        )
        if not handle:
            processes_restricted += 1
            continue
        processes_inspected += 1
        address = 0
        try:
            while True:
                memory_info = MemoryBasicInformation()
                result = kernel32.VirtualQueryEx(
                    handle, ctypes.c_void_p(address), ctypes.byref(memory_info), ctypes.sizeof(memory_info)
                )
                if not result:
                    break
                next_address = (memory_info.BaseAddress or 0) + memory_info.RegionSize
                if next_address <= address:
                    break
                if (
                    memory_info.State == mem_commit
                    and memory_info.Type == mem_private
                    and memory_info.Protect in executable_protections
                ):
                    private_executable_region_count += 1
                    if memory_info.Protect in {page_execute_readwrite, page_execute_writecopy}:
                        writable_executable_regions.append({
                            "process": process.get("ProcessName", "unknown"),
                            "process_id": process_id,
                            "address": f"0x{memory_info.BaseAddress:x}",
                            "size": memory_info.RegionSize,
                            "protection": f"0x{memory_info.Protect:02X}",
                        })
                address = next_address
        finally:
            kernel32.CloseHandle(handle)

    return {
        "processes_inspected": processes_inspected,
        "processes_restricted": processes_restricted,
        "private_executable_region_count": private_executable_region_count,
        "writable_executable_regions": writable_executable_regions,
        "writable_executable_process_count": len({
            (region["process"], region["process_id"])
            for region in writable_executable_regions
        }),
    }


def print_windows_memory_forensics() -> tuple[bool, bool]:
    """Run bounded live-process triage; this is not a raw memory acquisition."""
    if platform.system() != "Windows":
        print("MEMORY FORENSICS: unavailable — live process triage currently supports Windows only.")
        return False, False

    report = run_powershell(
        "$processes = @(Get-CimInstance Win32_Process -ErrorAction Stop); "
        "$commandLinePattern = '(?i)(-enc(?:odedcommand)?\\s+[a-z0-9+/=]{16,}|"
        "invoke-expression|\\biex\\b|downloadstring|frombase64string|rundll32(?:\\.exe)?\\s+[^,]+,|"
        "regsvr32(?:\\.exe)?.*(?:/i:|scrobj))'; "
        "$commandLineHits = @($processes | Where-Object { $_.ProcessId -ne $PID -and $_.CommandLine -match $commandLinePattern }); "
        "$moduleHits = [System.Collections.Generic.List[object]]::new(); "
        "$accessDenied = 0; "
        "foreach ($process in Get-Process -ErrorAction SilentlyContinue) { "
        "try { foreach ($module in $process.Modules) { "
        "if ($module.FileName -match '(?i)\\\\(users\\\\[^\\\\]+\\\\(appdata\\\\|downloads\\\\)|windows\\\\temp\\\\|temp\\\\)') { "
        "$moduleHits.Add([PSCustomObject]@{ Process = $process.ProcessName; ProcessId = $process.Id; Module = $module.FileName }) } } "
        "} catch { $accessDenied++ } }; "
        "$moduleProcessHits = @($moduleHits | Group-Object Process,ProcessId); "
        "[PSCustomObject]@{ ProcessCount = $processes.Count; CommandLineIndicatorCount = $commandLineHits.Count; "
        "UserWritableModuleCount = $moduleHits.Count; UserWritableModuleProcessCount = $moduleProcessHits.Count; ModuleAccessRestrictedCount = $accessDenied; "
        "CommandLineSamples = @($commandLineHits | Select-Object -First 10 Name,ProcessId,CommandLine); "
        "ModuleSamples = @($moduleProcessHits | Select-Object -First 10 | ForEach-Object { $_.Group | Select-Object -First 1 }) } | ConvertTo-Json -Depth 3 -Compress"
    )

    print("MEMORY FORENSICS: read-only live process triage")
    if not isinstance(report, dict):
        print("  [—] Live process telemetry: unavailable (run the terminal as Administrator if access is denied)")
        return False, False

    print(f"  [i] Processes inventoried: {report.get('ProcessCount', 'unknown')}")
    print(f"  [i] Suspicious command-line indicators: {report.get('CommandLineIndicatorCount', 'unknown')}")
    print(
        "  [i] Processes with modules from user-writable locations: "
        f"{report.get('UserWritableModuleProcessCount', 'unknown')} "
        f"({report.get('UserWritableModuleCount', 'unknown')} modules)"
    )
    restricted = report.get("ModuleAccessRestrictedCount", 0)
    if restricted:
        print(f"  [—] Processes with restricted module access: {restricted}")

    for sample in report.get("CommandLineSamples", []):
        print(f"  [!] Command line: {sample.get('Name', 'unknown')} (PID {sample.get('ProcessId', '?')})")
    for sample in report.get("ModuleSamples", []):
        print(f"  [!] Review module: {sample.get('Process', 'unknown')} (PID {sample.get('ProcessId', '?')}): {sample.get('Module', 'unknown')}")
    memory_report = inspect_windows_process_memory()
    if memory_report is None:
        print("  [—] Process-memory region inspection: unavailable")
        return True, False
    regions = memory_report["writable_executable_regions"]
    print(
        "  [i] Process-memory regions inspected: "
        f"{memory_report['processes_inspected']} processes; "
        f"{memory_report['processes_restricted']} restricted"
    )
    print(
        "  [i] Committed private executable regions: "
        f"{memory_report['private_executable_region_count']}"
    )
    print(
        "  [i] Writable executable private regions: "
        f"{len(regions)} across {memory_report['writable_executable_process_count']} processes"
    )
    displayed_processes = set()
    for region in regions:
        process_key = (region["process"], region["process_id"])
        if process_key in displayed_processes:
            continue
        displayed_processes.add(process_key)
        print(
            f"  [!] Review writable executable memory: {region['process']} "
            f"(PID {region['process_id']}), {region['address']}, "
            f"{format_size(region['size'])}, protection {region['protection']}"
        )
        if len(displayed_processes) == 10:
            break
    print("  [i] This inspects virtual-memory metadata only; it does not read, dump, or scan process-memory contents.")
    return True, True


def request_elevated_system_audit(target: Path) -> bool:
    """Ask Windows UAC to relaunch only the audit with Administrator access."""
    if platform.system() != "Windows":
        print("Administrator audit is unavailable — UAC elevation is Windows-only.")
        return False

    arguments = f'"{Path(__file__).resolve()}" "{target}" --system-audit --elevated-child'
    command = (
        "$process = Start-Process -FilePath '"
        + sys.executable.replace("'", "''")
        + "' -ArgumentList '"
        + arguments.replace("'", "''")
        + "' -Verb RunAs -Wait -PassThru; exit $process.ExitCode"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command], check=False
        )
    except OSError:
        print("  [!] Unable to request Administrator access.")
        return False
    if result.returncode:
        print("  [!] Administrator access was declined or the elevated audit could not start.")
        return False
    return True


def request_elevated_authentication_analysis(target: Path, hours: int, result_path: Path) -> bool:
    """Ask Windows UAC to relaunch only authentication event-log analysis."""
    if platform.system() != "Windows":
        print("Administrator authentication analysis is unavailable — UAC elevation is Windows-only.")
        return False

    arguments = (
        f'"{Path(__file__).resolve()}" "{target}" --auth-log-analysis '
        f'--auth-log-hours {hours} --auth-result-file "{result_path}" --elevated-child'
    )
    command = (
        "$process = Start-Process -FilePath '"
        + sys.executable.replace("'", "''")
        + "' -ArgumentList '"
        + arguments.replace("'", "''")
        + "' -Verb RunAs -Wait -PassThru; exit $process.ExitCode"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command], check=False
        )
    except OSError:
        print("  [!] Unable to request Administrator access.")
        return False
    if result.returncode:
        print("  [!] Administrator access was declined or the elevated analysis could not start.")
        return False
    return True


class SecurityHubHandler(BaseHTTPRequestHandler):
    """Serve the local security hub and its read-only authentication endpoint."""

    def do_GET(self) -> None:
        if urlparse(self.path).path != "/":
            self.send_error(404)
            return
        try:
            page = DEFAULT_HUB_PAGE.read_bytes()
        except OSError:
            self.send_error(500, "Security hub page is unavailable")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/api/authentication-analysis":
            self.send_error(404)
            return
        try:
            result = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), ".", "--auth-log-analysis", "--no-hash"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60, check=False,
                env={**os.environ, "PYTHONUTF8": "1"},
            )
            report = result.stdout
            if result.stderr:
                report += f"\n\nAnalysis error output:\n{result.stderr}"
            payload = {"ok": result.returncode == 0, "report": report}
        except (OSError, subprocess.TimeoutExpired) as error:
            payload = {"ok": False, "report": f"Authentication analysis could not start: {error}"}
        response = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, format: str, *args: object) -> None:
        return


def run_security_hub(port: int) -> None:
    """Run a browser dashboard bound only to the local machine."""
    server = ThreadingHTTPServer(("127.0.0.1", port), SecurityHubHandler)
    print(f"Security hub: http://127.0.0.1:{port}")
    print("The hub is local-only. Press Ctrl+C to stop it.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nSecurity hub stopped.")
    finally:
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Find potentially risky files using safe local heuristics."
    )
    parser.add_argument(
        "folder", nargs="?", default=".", type=Path,
        help="Folder to scan (default: current folder).",
    )
    parser.add_argument(
        "--no-hash", action="store_true",
        help="Do not calculate SHA-256 hashes for flagged files.",
    )
    parser.add_argument(
        "--deep", action="store_true",
        help="Inspect small files for suspicious static script and URL indicators.",
    )
    parser.add_argument(
        "--url-blacklist", type=Path, default=DEFAULT_URL_BLACKLIST,
        help="Local file of blocked domains, one per line (default: url_blacklist.txt).",
    )
    intel_mode = parser.add_mutually_exclusive_group()
    intel_mode.add_argument(
        "--online-intel", action="store_true",
        help="Refresh a public malware-host feed and cache it locally for future offline scans.",
    )
    intel_mode.add_argument(
        "--offline-intel", action="store_true",
        help="Use only the previously cached public malware-host feed; never connect to the internet.",
    )
    parser.add_argument(
        "--threat-intel-cache", type=Path, default=DEFAULT_THREAT_INTEL_CACHE,
        help="Path for the optional online threat-intelligence cache.",
    )
    parser.add_argument(
        "--os-check", action="store_true",
        help="Show Microsoft Defender, firewall, and Defender detection-history status on Windows.",
    )
    parser.add_argument(
        "--defender-quick-scan", action="store_true",
        help="Run a Microsoft Defender quick scan, then show OS security status (Windows only).",
    )
    parser.add_argument(
        "--system-audit", action="store_true",
        help="Inspect Windows persistence, services, drivers, listeners, and authentication telemetry.",
    )
    parser.add_argument(
        "--memory-forensics", action="store_true",
        help="Run read-only Windows live process and loaded-module triage (not a raw RAM dump).",
    )
    parser.add_argument(
        "--network-monitor", action="store_true",
        help="Inventory live Windows host-to-host TCP connections and owning process IDs.",
    )
    parser.add_argument(
        "--auth-log-analysis", action="store_true",
        help="Analyze Windows failed-logon events for repeated sources and accounts.",
    )
    parser.add_argument(
        "--auth-log-hours", type=int, default=24,
        help="Hours of failed-logon history to analyze (default: 24).",
    )
    parser.add_argument(
        "--elevated-system-audit", action="store_true",
        help="Request Administrator access, then run only the Windows system audit.",
    )
    parser.add_argument(
        "--elevated-auth-log-analysis", action="store_true",
        help="Request Administrator access, then run only authentication event-log analysis.",
    )
    parser.add_argument(
        "--web-hub", action="store_true",
        help="Start the local-only browser hub for authentication analysis.",
    )
    parser.add_argument(
        "--hub-port", type=int, default=8765,
        help="Local port for --web-hub (default: 8765).",
    )
    parser.add_argument("--auth-result-file", type=Path, default=None, help=argparse.SUPPRESS)
    parser.add_argument(
        "--elevated-child", action="store_true", help=argparse.SUPPRESS
    )
    args = parser.parse_args()

    if args.auth_log_hours <= 0:
        parser.error("--auth-log-hours must be greater than zero.")
    if not 1 <= args.hub_port <= 65535:
        parser.error("--hub-port must be between 1 and 65535.")

    if args.web_hub:
        run_security_hub(args.hub_port)
        return

    target = args.folder.expanduser().resolve()
    if not target.is_dir():
        parser.error(f"'{target}' is not a folder.")

    if args.elevated_system_audit:
        print("Requesting Administrator access for the Windows system audit...")
        request_elevated_system_audit(target)
        return
    if args.elevated_auth_log_analysis:
        print("Requesting Administrator access for authentication event-log analysis...")
        DEFAULT_AUTH_RESULT.unlink(missing_ok=True)
        if request_elevated_authentication_analysis(target, args.auth_log_hours, DEFAULT_AUTH_RESULT):
            print_saved_authentication_results(DEFAULT_AUTH_RESULT)
        return

    print("\n" + "=" * 64)
    print("                 LOCAL FILE RISK SCANNER")
    print("=" * 64)
    print(f"Scanning: {target}")
    print("Mode:     Read-only — scanned files are not changed or uploaded")
    url_blacklist = load_url_blacklist(args.url_blacklist)
    intel_hosts = set()
    intel_status = "not requested"
    if args.online_intel or args.offline_intel:
        intel_hosts, intel_status = load_online_threat_intel(
            args.threat_intel_cache, args.offline_intel
        )
        url_blacklist.update(intel_hosts)
    print(f"Analysis: {'Filename and content indicators' if args.deep else 'Filename indicators only'}")
    print(f"URL list:  {len(url_blacklist)} local blocked domain(s) loaded" if url_blacklist else "URL list:  no local blacklist loaded")
    if args.online_intel or args.offline_intel:
        print(f"Web intel: {intel_status} ({len(intel_hosts)} hostnames)")
    print("-" * 64)

    findings, files_checked, files_skipped, diagnostics = scan(
        target, not args.no_hash, args.deep, url_blacklist
    )

    if findings:
        for number, finding in enumerate(findings, start=1):
            print(f"[{number}] {finding.path}")
            print(f"    Size:    {format_size(finding.size)}")
            print(f"    Priority: {finding.severity}")
            print(f"    Reasons: {'; '.join(finding.reasons)}")
            if finding.sha256:
                print(f"    SHA-256: {finding.sha256}")
        print("-" * 64)
        print(f"Result: {len(findings)} file(s) need review.")
    else:
        print("Result: No files matching the scanner's risk rules were found.")

    print("-" * 64)
    print("DIAGNOSTIC CHECKLIST")
    print_check("Risky executable or script file types", diagnostics["risky_file_types"])
    print_check("Misleading double extensions", diagnostics["double_extensions"])
    print_check("Hidden executable or script files", diagnostics["hidden_scripts"])
    print_check("PowerShell encoded commands", diagnostics["PowerShell encoded command"], args.deep)
    print_check("PowerShell download patterns", diagnostics["PowerShell download cradle"], args.deep)
    print_check("PowerShell expression execution", diagnostics["PowerShell expression execution"], args.deep)
    print_check("Command-shell execution patterns", diagnostics["Command shell execution"], args.deep)
    print_check("Encoded-content decoding", diagnostics["Script created from encoded content"], args.deep)
    print_check("Potential remote payload URLs", diagnostics["Potential remote payload URL"], args.deep)
    print_check("URLs matching local blacklist", diagnostics["URL matched local blacklist"], args.deep and bool(url_blacklist))
    if args.no_hash:
        print("  [—] SHA-256 hashes: not checked")
    else:
        hashes_created = sum(finding.sha256 is not None for finding in findings)
        hashes_skipped = sum("SHA-256 skipped" in reason for finding in findings for reason in finding.reasons)
        print(f"  [i] SHA-256 hashes: enabled ({hashes_created} created; {hashes_skipped} skipped due to size)")
    print(f"  [i] Files checked: {files_checked} | Symlinks skipped: {files_skipped}")
    print("-" * 64)
    memory_forensics_ran = False
    process_memory_inspection_ran = False
    network_monitor_ran = False
    auth_log_analysis_ran = False
    if args.memory_forensics:
        print("-" * 64)
        memory_forensics_ran, process_memory_inspection_ran = print_windows_memory_forensics()
    if args.network_monitor:
        print("-" * 64)
        network_monitor_ran = print_windows_network_monitor()
    if args.auth_log_analysis:
        print("-" * 64)
        auth_log_analysis_ran = print_windows_authentication_analysis(
            args.auth_log_hours, args.auth_result_file
        )
        if auth_log_analysis_ran is None and not args.elevated_child:
            print("Requesting Administrator access to complete authentication event-log analysis...")
            DEFAULT_AUTH_RESULT.unlink(missing_ok=True)
            if request_elevated_authentication_analysis(target, args.auth_log_hours, DEFAULT_AUTH_RESULT):
                print_saved_authentication_results(DEFAULT_AUTH_RESULT)
            return
    print_threat_coverage(
        diagnostics, args.deep, memory_forensics_ran, process_memory_inspection_ran,
        network_monitor_ran, auth_log_analysis_ran,
    )
    print_assessment("Exploit / bypass:", "not assessed — requires vulnerability and behavior analysis")
    print_assessment("Zero-day:", "not detectable by static checks; no signature or known rule exists")
    if args.os_check or args.defender_quick_scan:
        print("-" * 64)
        print_windows_security_diagnostics(args.defender_quick_scan)
    if args.system_audit:
        print("-" * 64)
        print_windows_system_audit()
    print("Note: This is a heuristic review tool, not an antivirus engine.")
    print("It cannot reliably identify unknown zero-days or prove a file is safe.")
    print("=" * 64 + "\n")


if __name__ == "__main__":
    main()

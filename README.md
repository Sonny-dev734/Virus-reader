# 🛡️ Local File Risk Scanner

<p align="center">
  <strong>A tiny, standalone Python utility for finding files worth reviewing.</strong><br>
  <sub>Read-only • Dependency-free • No uploads</sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/Dependencies-none-2ea44f" alt="No dependencies">
  <img src="https://img.shields.io/badge/Mode-read--only-0ea5e9" alt="Read-only">
</p>

---

## What it does

`virus_reader.py` recursively checks a chosen folder and flags files that match clear, local risk rules:

- Executable or script extensions such as `.exe`, `.ps1`, `.bat`, `.js`, and `.vbs`
- Potentially misleading names with double extensions, such as `invoice.pdf.exe`
- Hidden executable or script files
- SHA-256 hashes for flagged files up to 100 MiB

Use deep mode to also inspect small files for static indicators commonly seen in suspicious scripts, including encoded PowerShell commands, download cradles, command-shell launches, encoded-content decoding, remote payload URLs, input-capture APIs, persistence commands, ransomware recovery-inhibition commands, and cryptomining markers.

### Local URL blacklist

When `--deep` is enabled, discovered URLs are compared with [url_blacklist.txt](url_blacklist.txt), a local list of blocked domains. Add one domain per line; subdomains match automatically. The included `.invalid` entry is only a safe example, so add domains from a trusted threat-intelligence source before relying on it.

Use a different local list when needed:

```powershell
python virus_reader.py "C:\Users\admin\Downloads" --deep --url-blacklist "C:\path\to\blocked-domains.txt"
```

The scanner does not send URLs or files to the internet.

### Windows OS security check

On Windows, use the built-in Microsoft Defender engine for an operating-system-level check:

```powershell
.\run_virus_reader.bat --os-check
```

Run a real Microsoft Defender quick scan and show its protection evidence:

```powershell
python .\virus_reader\virus_reader.py . --deep --defender-quick-scan
```

The OS check reports Defender service, real-time and behavior protection, signature update time, firewall profiles, and Defender detection history. It is evidence of the current Windows security state, not proof that no compromise or zero-day exists.

### Windows system audit

The launcher now includes the system audit automatically. It uses only Python's standard library plus Windows PowerShell commands already present on Windows—there are no packages to install.

The audit inventories startup entries, enabled scheduled tasks, running services, loaded kernel drivers, listening ports, Microsoft Defender exclusions, UAC, and failed logons from the previous 24 hours. It does not delete files, change settings, send data to the internet, or claim that an inventory count proves malware.

Some event-log and system queries may require an elevated terminal. When access is unavailable, the tool shows `unavailable` rather than treating it as a clean result. Open PowerShell as Administrator and rerun the launcher to request the permissions Windows requires.

To request Windows Administrator access only for the audit, run:

```powershell
.\run_virus_reader.bat --elevated-system-audit
```

Windows will show a UAC confirmation prompt. Accept it to run the child audit with elevated event-log access; decline it to leave the system unchanged.

Every scan ends with a **diagnostic checklist**. Each check is marked as:

- `[✓]` no matching indicator detected
- `[!]` one or more matching indicators detected
- `[—]` not checked because `--deep` or hashing was disabled

It also provides a **threat-type quick rundown**. The static checks can only report *indicators* relevant to malware, trojans/droppers, RATs/backdoors, spyware/keyloggers, ransomware/wipers, cryptojacking, fileless malware, and browser-hijacking persistence. A match is not proof of malware.

Memory-resident malware, malvertising, rootkits, kernel control, DDoS, rogue security software, brute force, phishing communications, exploits/bypasses, and zero-days are explicitly reported as **not assessed**. Reliable checks for these need specialized endpoint detection, memory forensics, vulnerability intelligence, or live process, authentication, and network telemetry—not a local static file scan.

### Windows memory forensics triage

Use the optional live process-memory triage to inventory running processes, identify suspicious process command-line indicators, flag loaded modules executing from user-writable locations, and inspect virtual-memory region metadata for committed private executable regions:

```powershell
python virus_reader.py . --memory-forensics
```

The top-level `run_virus_reader.bat` launcher includes this check automatically.

This feature uses built-in Windows telemetry and Windows process APIs, does not modify or upload scanned files, and does not read, dump, or scan process-memory contents. It reports metadata that can identify regions worth investigating. It is **not** a full memory-forensics engine: protected processes may restrict access, and an absence of findings does not prove that memory-resident malware or RAM scraping is absent. Run PowerShell as Administrator for broader process visibility.

### Online and offline web intelligence

The scanner is offline by default. To retrieve the public URLhaus malware-host feed, cache it locally, and compare discovered URLs against it during a deep scan:

```powershell
python virus_reader.py . --deep --online-intel
```

For an offline scan using only that previously saved cache, use `--offline-intel`. This is the only mode that connects to the web, and it downloads one documented plain-text threat feed; files are never uploaded.

### Windows host-to-host monitoring

Use `--network-monitor` to take a read-only snapshot of established remote TCP connections and their owning process IDs:

```powershell
python virus_reader.py . --network-monitor
```

This helps identify network activity that merits investigation, but it does not capture packets or prove that a worm is propagating.

### Windows authentication event analysis

Use `--auth-log-analysis` to summarize failed Windows logons (Event ID 4625) from the previous 24 hours, including repeated remote source IPs and target accounts:

```powershell
python virus_reader.py . --auth-log-analysis
```

Use `--auth-log-hours 72` for a 72-hour window. This reads the local Security event log only; administrator access may be needed. If Windows denies the initial read, the scanner automatically requests UAC approval and relaunches only the authentication analysis as an elevated child. After approval, the elevated result is saved locally and displayed back in the original terminal or Security Hub. Repeated failures are investigation signals, not proof of a brute-force attack.

To request Windows Administrator access for only this check, run:

```powershell
python virus_reader.py . --elevated-auth-log-analysis
```

### Local security hub

Run the translucent local dashboard with:

```powershell
.\run_hub.bat
```

Then open `http://127.0.0.1:8765`. The hub listens only on your computer and its authentication-analysis button runs the same read-only event-log query as the command-line scanner.

## Quick start

Run this from the `virus_reader` folder to scan the current folder with the default deep, no-hash scan:

```powershell
.\run
```

In Command Prompt, use `run`. To use `run` without `./` in PowerShell, add this folder to your `PATH`.

Run the Python script directly to scan the current folder:

```powershell
python virus_reader.py
```

Scan another folder by giving its path:

```powershell
python virus_reader.py "C:\Users\admin\Downloads"
```

Skip hashing if you only want the fast filename check:

```powershell
python virus_reader.py "C:\Users\admin\Downloads" --no-hash
```

Inspect file contents as well as names:

```powershell
python virus_reader.py "C:\Users\admin\Downloads" --deep
```

## Example

```text
[1] C:\Users\admin\Downloads\invoice.pdf.exe
    Size:    84.0 KiB
    Priority: HIGH — review promptly
    Reasons: Executable or script file (.exe); Potentially misleading double extension
    SHA-256: 4f35...a8c1

Result: 1 file(s) need review.
```

## Important limitations

This is **not an antivirus product**. It uses transparent static heuristics and does not have a malware-signature database, behavioral analysis, memory scanning, or network intrusion detection. A flagged file is not automatically malicious, and an unflagged file is not automatically safe.

It cannot reliably detect a previously unknown **zero-day** exploit. If there is an active concern, keep the system and security software updated, disconnect from untrusted networks when appropriate, and use a trusted endpoint-security product or security professional for investigation.

- It never changes, deletes, quarantines, or uploads files.
- It does not scan inside archives or inspect file contents.
- Use Windows Security or another trusted antivirus solution for full malware protection.

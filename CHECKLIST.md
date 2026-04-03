# Functional Operations Checklist

The following is a breakdown of the automated operations Aura-Executive uses, whether they currently work seamlessly cross-platform, and exactly how the pipeline processes the steps.

| Module / Operation | Tool Executed | OS Compatibility | Functionality / How It Works |
| :--- | :--- | :--- | :--- |
| **Dependency Check** | Native Python | Windows & Linux (✅) | Prior to execution, the framework verifies Python packages (`requests`, `pyfiglet`), returning gracefully with an install command if absent. |
| **Tool Preflight** | `shutil.which` / `--help` | Windows & Linux (✅) | Checks `$PATH` for over a dozen required tool binaries (e.g. `subfinder`, `httpx`). Missing optional tools are bypassed automatically. |
| **Discovery** | `subfinder`, `assetfinder`, `amass` | Windows & Linux (✅) | The pipeline fires these commands concurrently gathering subdomains. Raw outputs are pushed to `<target>/results/` and safely concatenated without bash overlaps. |
| **List Deduplication** | `Python Sets` (Previously `sort -u`) | Windows & Linux (✅) | Replaces standard GNU `LC_ALL=C sort` via seamless and lightweight built-in memory mapping (`set()`). Fully cross-platform. |
| **Passive Recon** | `gau`, `waybackurls` | Windows & Linux (✅) | Gathers archived endpoints. Overcomes Windows `echo` spacing limits utilizing safe python injection. |
| **Active Probing** | `httpx`, `httprobe` | Windows & Linux (✅) | Validates active webservers. Windows pipelines dynamically adapt by converting standard bash `cat <file> \| httprobe` to native `type <file> \| httprobe` streams. |
| **Port Scanning** | `naabu`, `nmap` | Linux (✅) / Partial Win (🟡) | Native concurrency checks ports. `nmap` integrates well across platforms, executing only against previously confirmed hosts to prevent blocking. |
| **Path Fuzzing** | `ffuf` | Windows & Linux (✅) | Performs brute-force operations for hidden assets. Can scale up with `--full-scan` and specified wordlists limitlessly. |
| **Vulnerability Sweep** | `nuclei` | Windows & Linux (✅) | Ingests the unified manifest via standard flags to deploy critical, high severity, or anomalous CVE templates. |

## Why it works flawlessly across Windows
Traditional bash scripts natively chain pipes `stdout -> stdin`. Aura-Executive's orchestration intercepts these paths natively via `asyncio.create_subprocess_shell()`, ensuring file pointers are evaluated against their operative system configuration limits (`sys.platform`), allowing for direct drop-in functionality on Windows systems.

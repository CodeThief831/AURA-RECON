# AURA-EXECUTIVE / BountyBot 🕵️‍♂️✨
> ***"An autonomous Red Team Agent specialized in Bug Bounty reconnaissance."***

Aura-Executive is an automated, async-driven bug bounty orchestrator capable of aggressive and passive reconnaissance using modern utilities in a unified pipeline. It employs a ReAct cognitive framework (THOUGHT, ACTION, OBSERVATION, REFINEMENT) structurally to map an organization's attack surface deeply before testing vulnerabilities.

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9+-blue" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-green" alt="Multiplatform">
  <img src="https://img.shields.io/badge/Role-Red%20Team-red" alt="Red Team Agent">
</p>

## The Operational Strategy 🧠

Aura-Executive enforces an **exact sequence strategy** structurally across its codebase:
1. **Methodical Depth:** Never scan for vulnerabilities until a verified list of active hosts is confirmed to ensure stealth and efficiency.
2. **Data Persistence:** Automatically structure targets into organized domains, open ports, footprints, and findings safely tracked in a unified, per-target `/results` manifest.
3. **Pivot Logic:** Accurately discover unique headers or services, passing intelligence to active tools downstream seamlessly.

**Constraint:** Designed and constrained for authorized targets *only*. The goal is to evaluate attack surfaces *before* threat actors. Accuracy, stealth, and logical filtering parameters are baked into the pipeline.

## Arsenal & Definitions ⚔️

Each action of the automated loop relies on integrated system binaries:
* **`enumerate_subdomains`:** `subfinder`, `assetfinder`, and `amass` to expand the attack tree.
* **`probe_live_hosts`:** `httpx` and `httprobe` specifically searching out web services cleanly without false positive noise.
* **`port_scan`:** `naabu` with a fallback to deep `nmap -sV` for accurate fingerprinting and service detection.
* **`vulnerability_scan`:** Fast and seamless `nuclei` scanning over the active target list (e.g., critical & high severity templates).
* **`directory_brute`:** Sub-process concurrent `ffuf` on web roots targeting administrative panels and APIs automatically.

## Requirements 🛠️
You must have the underlying tools installed natively and available in your `PATH` or `$GOPATH/bin`. 
Common Go packages required for the base functionality:
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# Note: See preflight check for complete definitions.
```

Install the Python orchestration dependencies via the `requirements.txt`:
```bash
pip install -r requirements.txt
```

## Usage 🚀

Aura-Executive allows checking preflight compatibility directly on any OS (Linux/Windows).
```bash
# Verify your arsenal
python bounty_bot.py --check-tools
```

Once dependencies are verified, execute your first run utilizing the native shell script `./aura.sh` (Linux/Mac/Git Bash) or `.\aura.bat` (Windows):
```bash
# On Linux or Mac:
./aura.sh --target example.com --authorized --threads 10

# On Windows:
.\aura.bat --target example.com --authorized --threads 10
```
*Note: The `--authorized` flag is required as a final safety check confirming the target domain operates within your defined scope or bug bounty program.*

---
**Disclaimer:** *Aura-Executive orchestrates powerful tools aggressively mapping and probing web infrastructure. DO NOT launch scans against hosts you do not have explicitly authorized permission to test.*

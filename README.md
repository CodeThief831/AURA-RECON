# AURA-RECON / BountyBot 🕵️‍♂️✨
> ***"An autonomous Red Team Agent specialized in Bug Bounty reconnaissance."***

Aura-Recon is an automated, async-driven bug bounty orchestrator capable of aggressive and passive reconnaissance using modern utilities in a unified pipeline. It employs a **ReAct cognitive framework** (THOUGHT → ACTION → OBSERVATION → REFINEMENT) to deeply map an organization's attack surface before any vulnerability testing begins.

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9+-blue" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-green" alt="Multiplatform">
  <img src="https://img.shields.io/badge/Role-Red%20Team-red" alt="Red Team Agent">
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="MIT License">
</p>

---

## Table of Contents 📚

1. [Operational Strategy](#the-operational-strategy-)
2. [Arsenal & Definitions](#arsenal--definitions-️)
3. [Installation](#installation-)
   - [Clone the Repository](#1-clone-the-repository)
   - [Install Go Tools](#2-install-go-tools-in-path)
   - [Install Python Dependencies](#3-install-python-dependencies)
4. [Usage](#usage-)
5. [Project Structure](#project-structure-)
6. [Disclaimer](#disclaimer)

---

## The Operational Strategy 🧠

Aura-Recon enforces an **exact sequence strategy** across its codebase:

1. **Methodical Depth:** Never scan for vulnerabilities until a verified list of active hosts is confirmed — ensuring stealth and efficiency.
2. **Data Persistence:** Automatically structures targets into organized domains, open ports, footprints, and findings tracked in a unified per-target `/results` manifest.
3. **Pivot Logic:** Accurately discovers unique headers or services, passing intelligence to active tools downstream seamlessly.

> **Constraint:** Designed and constrained for **authorized targets only**. The goal is to evaluate attack surfaces *before* threat actors. Accuracy, stealth, and logical filtering are baked into the pipeline.

---

## Arsenal & Definitions ⚔️

Each action of the automated loop relies on integrated system binaries:

| Action | Tool(s) | Purpose |
|---|---|---|
| `enumerate_subdomains` | `subfinder`, `assetfinder`, `amass` | Expand the attack tree |
| `probe_live_hosts` | `httpx`, `httprobe` | Identify live web services without false positives |
| `port_scan` | `naabu` → `nmap -sV` (fallback) | Accurate fingerprinting and service detection |
| `vulnerability_scan` | `nuclei` | Fast template-based scanning (critical & high severity) |
| `directory_brute` | `ffuf` | Concurrent bruteforcing of web roots for panels and APIs |

---

## Installation 🛠️

### 1. Clone the Repository

```bash
git clone https://github.com/CodeThief831/AURA-RECON.git
cd AURA-RECON
```

> **Windows users:** Use Git Bash, PowerShell, or Windows Terminal. Both `aura.bat` (Windows) and `aura.sh` (Linux/Mac) are included.

---

### 2. Install Go Tools (in PATH)

Ensure Go is installed (`go version`), then install the required reconnaissance binaries:

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/tomnomnom/httprobe@latest
go install -v github.com/ffuf/ffuf/v2@latest
```

> After installation, make sure `$GOPATH/bin` (Linux/Mac) or `%USERPROFILE%\go\bin` (Windows) is added to your system `PATH`.

---

### 3. Install Python Dependencies

```bash
pip install -r requirements.txt
```

**`requirements.txt` includes:**
```
pyyaml==6.0.1
pyfiglet==1.0.2
requests==2.32.3
```

---

## Usage 🚀

### Preflight Check

Verify all tools are available in your `PATH` before running:

```bash
python bounty_bot.py --check-tools
```

### Run a Scan

Once dependencies are verified, execute your scan using the native wrapper:

```bash
# On Linux / Mac / Git Bash:
./aura.sh --target example.com --authorized --threads 10

# On Windows (Command Prompt or PowerShell):
.\aura.bat --target example.com --authorized --threads 10
```

> **Note:** The `--authorized` flag is **required** as a final safety check confirming the target domain is within your defined scope or bug bounty program.

---

## Project Structure 📁

```
AURA-RECON/
├── bounty_bot.py       # Core async orchestrator (ReAct agent loop)
├── lab.py              # Experimental / lab testing module
├── aura.sh             # Unix launcher script
├── aura.bat            # Windows launcher script
├── requirements.txt    # Python dependencies
├── CHECKLIST.md        # Pre-engagement checklist
├── .gitignore          # Git ignore rules
├── LICENSE             # MIT License
└── results/            # Per-target output (gitignored)
```

---

## Disclaimer

> **⚠️ IMPORTANT:** Aura-Recon orchestrates powerful tools that aggressively map and probe web infrastructure.
>
> **DO NOT** launch scans against hosts you do not have **explicitly authorized permission** to test. The author is not responsible for misuse. Always operate within the rules of your bug bounty program or with written authorization from the target organization.

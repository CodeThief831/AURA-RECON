from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

if sys.platform == "win32":
    go_bin = str(Path.home() / "go" / "bin")
    if go_bin not in os.environ.get("PATH", ""):
        os.environ["PATH"] = f"{go_bin};{os.environ.get('PATH', '')}"

try:
    import requests
    from lab import run_request_lab
except ImportError:
    raise SystemExit("[!] Missing required modules. Please install dependencies: pip install -r requirements.txt")

try:
    from pyfiglet import figlet_format
except ImportError:
    figlet_format = None


DISCOVERY_TOOLS = ("subfinder", "assetfinder", "amass")
PASSIVE_RECON_TOOLS = ("gau", "waybackurls", "dnsx", "httprobe")
CRAWL_TOOLS = ("katana",)
FINGERPRINT_TOOLS = ("whatweb",)
LAB_TOOLS = ("sublist3r", "sqlmap", "commix")
SYSTEM_DNS_TOOLS = ("dig", "nslookup")
REQUIRED_TOOLS = ("httpx", "nuclei")
OPTIONAL_TOOLS = ("nmap", "ffuf", "naabu",) + PASSIVE_RECON_TOOLS + CRAWL_TOOLS + FINGERPRINT_TOOLS + LAB_TOOLS + SYSTEM_DNS_TOOLS

if sys.platform == "win32":
    LINUX_ONLY = {"nmap", "whatweb", "sublist3r", "sqlmap", "commix", "dig"}
    OPTIONAL_TOOLS = tuple(t for t in OPTIONAL_TOOLS if t not in LINUX_ONLY)
WEB_PORTS = {
    80,
    81,
    82,
    88,
    443,
    444,
    8000,
    8001,
    8008,
    8080,
    8081,
    8088,
    8888,
    9000,
    9001,
    9090,
    9443,
    10000,
}
if sys.platform == "win32":
    DEFAULT_WORDLIST = str(Path.home() / "wordlists" / "common.txt")
else:
    DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"

# On Windows, some tools hang when probed with -h / -version due to stdin blocking.
# We skip probing those and mark them available-only via shutil.which.
_WIN_SKIP_PROBE = {"naabu", "nslookup", "httpx", "httprobe", "gau", "waybackurls"}

TOOL_PROBES: Dict[str, List[str]] = {
    "subfinder": ["subfinder", "-version"],
    "assetfinder": ["assetfinder", "-h"],
    "amass": ["amass", "-version"],
    "sublist3r": ["sublist3r", "-h"],
    "gau": ["gau", "-h"],
    "waybackurls": ["waybackurls", "-h"],
    "dnsx": ["dnsx", "-h"],
    "httprobe": ["httprobe", "-h"],
    "katana": ["katana", "-h"],
    "whatweb": ["whatweb", "--help"],
    "sqlmap": ["sqlmap", "-h"],
    "commix": ["commix", "-h"],
    "dig": ["dig", "-v"],
    "nslookup": ["nslookup", "-version"],
    "naabu": ["naabu", "-version"],
    "nmap": ["nmap", "--version"],
    "httpx": ["httpx", "-version"],
    "ffuf": ["ffuf", "-V"],
    "nuclei": ["nuclei", "-version"],
}


@dataclass
class CommandResult:
    tool: str
    command: str
    returncode: int
    stdout: str
    stderr: str
    started_at: float
    finished_at: float

    @property
    def elapsed_ms(self) -> int:
        return int((self.finished_at - self.started_at) * 1000)


@dataclass
class ChainRecord:
    stage: str
    tool: str
    command: str
    input_files: List[str] = field(default_factory=list)
    output_files: List[str] = field(default_factory=list)
    returncode: int = 0
    elapsed_ms: int = 0
    note: str = ""


@dataclass
class ToolCheck:
    name: str
    available: bool
    probed: bool
    probe_ok: bool
    probe_output: str = ""
    install_hint: str = ""


def banner() -> None:
    title = figlet_format("AURA-RECON", font="slant") if figlet_format else "AURA-RECON"
    print(title)
    print("Async bug bounty recon for authorized targets only.\n")


def sanitize_target(target: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9._-]+", "_", target.strip().lower())
    return clean.strip("_.-") or "target"


def shell_quote(value: str) -> str:
    return shlex.quote(value)


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def install_hint(tool: str) -> str:
    hints = {
        "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "assetfinder": "go install github.com/tomnomnom/assetfinder@latest",
        "amass": "go install -v github.com/owasp-amass/amass/v4/...@master",
        "sublist3r": "pip install sublist3r",
        "gau": "go install github.com/lc/gau/v2/cmd/gau@latest",
        "waybackurls": "go install github.com/tomnomnom/waybackurls@latest",
        "dnsx": "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        "httprobe": "go install github.com/tomnomnom/httprobe@latest",
        "katana": "go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
        "whatweb": "sudo apt install whatweb",
        "sqlmap": "sudo apt install sqlmap",
        "commix": "git clone https://github.com/commixproject/commix.git",
        "dig": "sudo apt install dnsutils",
        "nslookup": "sudo apt install dnsutils",
        "naabu": "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        "nmap": "sudo apt install nmap",
        "httpx": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "ffuf": "go install github.com/ffuf/ffuf/v2@latest",
        "nuclei": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "sort": "Install GNU coreutils or ensure sort is in PATH",
    }
    return hints.get(tool, "Install the tool and ensure it is in PATH")


async def probe_tool(tool: str, semaphore: asyncio.Semaphore) -> ToolCheck:
    available = tool_available(tool)
    if not available:
        return ToolCheck(
            name=tool,
            available=False,
            probed=False,
            probe_ok=False,
            install_hint=install_hint(tool),
        )

    # Skip probing tools known to hang on Windows (stdin-blocking or version-flag issues)
    if sys.platform == "win32" and tool in _WIN_SKIP_PROBE:
        return ToolCheck(
            name=tool,
            available=True,
            probed=False,
            probe_ok=True,
            probe_output="(probe skipped on Windows — binary found in PATH)",
            install_hint=install_hint(tool),
        )

    probe = TOOL_PROBES.get(tool)
    if not probe:
        return ToolCheck(
            name=tool,
            available=True,
            probed=False,
            probe_ok=True,
            install_hint=install_hint(tool),
        )

    async with semaphore:
        try:
            exe_path = shutil.which(probe[0]) or probe[0]
            process = await asyncio.create_subprocess_exec(
                exe_path,
                *probe[1:],
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_data, stderr_data = await asyncio.wait_for(process.communicate(), timeout=8.0)
            except asyncio.TimeoutError:
                try:
                    process.kill()
                    await asyncio.sleep(0)
                except OSError:
                    pass
                return ToolCheck(
                    name=tool,
                    available=True,
                    probed=True,
                    probe_ok=False,
                    probe_output="Command timed out",
                    install_hint=install_hint(tool),
                )
        except OSError:
            return ToolCheck(
                name=tool,
                available=False,
                probed=False,
                probe_ok=False,
                install_hint=install_hint(tool),
            )

    output = (stdout_data + stderr_data).decode("utf-8", errors="replace").strip()
    probe_ok = process.returncode == 0 or bool(output)
    return ToolCheck(
        name=tool,
        available=True,
        probed=True,
        probe_ok=probe_ok,
        probe_output=output[:400],
        install_hint=install_hint(tool),
    )


async def preflight_tools(semaphore: asyncio.Semaphore, *, require_optional: bool = False) -> List[ToolCheck]:
    checks = await asyncio.gather(*[probe_tool(tool, semaphore) for tool in (DISCOVERY_TOOLS + REQUIRED_TOOLS + OPTIONAL_TOOLS)])
    failures: List[str] = []
    missing_discovery = [check.name for check in checks if check.name in DISCOVERY_TOOLS and not check.available]
    missing_required = [check.name for check in checks if check.name in REQUIRED_TOOLS and not check.available]
    missing_optional = [check.name for check in checks if check.name in OPTIONAL_TOOLS and not check.available]

    if len(missing_discovery) == len(DISCOVERY_TOOLS):
        failures.append("No discovery tool is installed. Install at least one of: subfinder, assetfinder, amass.")
    if missing_required:
        failures.append("Missing required tools: " + ", ".join(missing_required))
    if require_optional and missing_optional:
        failures.append("Missing optional tools requested as required: " + ", ".join(missing_optional))

    print("[+] Tool preflight results:")
    for check in checks:
        state = "ok" if check.available and check.probe_ok else "missing" if not check.available else "needs attention"
        print(f"    - {check.name}: {state}")
        if check.available and check.probed and check.probe_output:
            first_line = check.probe_output.splitlines()[0]
            print(f"      {first_line}")
        if not check.available:
            print(f"      install: {check.install_hint}")

    if failures:
        raise SystemExit("\n".join(failures))

    missing_optional = [check.name for check in checks if check.name in OPTIONAL_TOOLS and not check.available]
    if missing_optional:
        print("[!] Optional tools not installed; the pipeline will continue without them:")
        for tool in missing_optional:
            print(f"    - {tool}: {install_hint(tool)}")

    return checks


def read_lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]


def write_lines(path: Path, lines: Iterable[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    values = [line.strip() for line in lines if line and line.strip()]
    text = "\n".join(values)
    if values:
        text += "\n"
    path.write_text(text, encoding="utf-8")


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


async def run_shell(command: str, semaphore: asyncio.Semaphore, *, cwd: Optional[Path] = None) -> CommandResult:
    async with semaphore:
        started_at = time.time()
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(cwd) if cwd else None,
        )
        stdout_data, stderr_data = await process.communicate()
        finished_at = time.time()
        return CommandResult(
            tool="shell",
            command=command,
            returncode=process.returncode,
            stdout=stdout_data.decode("utf-8", errors="replace"),
            stderr=stderr_data.decode("utf-8", errors="replace"),
            started_at=started_at,
            finished_at=finished_at,
        )


async def run_tool_command(tool: str, command: str, semaphore: asyncio.Semaphore, *, cwd: Optional[Path] = None) -> CommandResult:
    result = await run_shell(command, semaphore, cwd=cwd)
    result.tool = tool
    return result


async def sort_unique(source: Path, destination: Path, semaphore: asyncio.Semaphore) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not source.exists():
        write_lines(destination, [])
        return

    if tool_available("sort") and sys.platform != "win32":
        command = f"LC_ALL=C sort -u {shell_quote(str(source))} -o {shell_quote(str(destination))}"
        result = await run_tool_command("sort", command, semaphore)
        if result.returncode == 0:
            return

    unique_lines = sorted({line.strip() for line in read_lines(source) if line.strip()})
    write_lines(destination, unique_lines)


def parse_nmap_xml(xml_text: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if not xml_text.strip():
        return findings

    root = ET.fromstring(xml_text)
    for host in root.findall("host"):
        hostnames = [item.attrib.get("name", "") for item in host.findall("hostnames/hostname")]
        hostname = next((name for name in hostnames if name), "")
        address_node = host.find("address")
        address = address_node.attrib.get("addr", "") if address_node is not None else ""
        target_label = hostname or address
        ports_node = host.find("ports")
        if ports_node is None:
            continue

        for port in ports_node.findall("port"):
            state_node = port.find("state")
            if state_node is None or state_node.attrib.get("state") != "open":
                continue
            service_node = port.find("service")
            service: Dict[str, Any] = {}
            if service_node is not None:
                service = dict(service_node.attrib)
                cpes = [item.text for item in service_node.findall("cpe") if item.text]
                if cpes:
                    service["cpe"] = cpes
            findings.append(
                {
                    "target": target_label,
                    "address": address,
                    "protocol": port.attrib.get("protocol", "tcp"),
                    "port": int(port.attrib.get("portid", "0")),
                    "state": state_node.attrib.get("state", "open"),
                    "reason": state_node.attrib.get("reason", ""),
                    "service": service,
                }
            )
    return findings


def parse_httpx_json_lines(jsonl_text: str) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    for line in jsonl_text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = entry.get("url") or entry.get("input") or ""
        if not url:
            continue
        records.append(entry)
    return records


def parse_ffuf_json(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return []

    results = payload.get("results", [])
    findings: List[Dict[str, Any]] = []
    for item in results:
        findings.append(
            {
                "url": item.get("url", ""),
                "status": item.get("status"),
                "length": item.get("length"),
                "words": item.get("words"),
                "lines": item.get("lines"),
                "input": item.get("input", {}),
                "redirectlocation": item.get("redirectlocation", ""),
                "scraper": item.get("scraper", {}),
            }
        )
    return findings


def dedupe_lines(values: Iterable[str]) -> List[str]:
    return list(dict.fromkeys(item.strip() for item in values if item and item.strip()))


def build_discovery_command(tool: str, target: str, full_scan: bool) -> str:
    if tool == "subfinder":
        return f"subfinder -d {shell_quote(target)} -silent -all"
    if tool == "assetfinder":
        return f"assetfinder --subs-only {shell_quote(target)}"
    if tool == "amass":
        mode = "-active" if full_scan else "-passive"
        return f"amass enum {mode} -d {shell_quote(target)}"
    raise ValueError(f"Unknown discovery tool: {tool}")


def build_passive_command(tool: str, target: str) -> str:
    if tool == "gau":
        return f"gau {shell_quote(target)}"
    if tool == "waybackurls":
        if sys.platform == "win32":
            return f"echo {target}| waybackurls"
        return f"printf '%s\\n' {shell_quote(target)} | waybackurls"
    raise ValueError(f"Unknown passive tool: {tool}")


async def run_discovery(target: str, output_dir: Path, semaphore: asyncio.Semaphore, full_scan: bool, chain: List[ChainRecord]) -> Path:
    available_tools = [tool for tool in DISCOVERY_TOOLS if tool_available(tool)]
    if not available_tools:
        raise SystemExit("No discovery tools available. Install at least one of: subfinder, assetfinder, amass.")

    raw_files: List[Path] = []
    tasks = []
    for tool in available_tools:
        raw_path = output_dir / f"{tool}_raw.txt"
        raw_files.append(raw_path)
        command = build_discovery_command(tool, target, full_scan)
        tasks.append((tool, raw_path, command))

    results = await asyncio.gather(
        *[
            run_tool_command(tool, command, semaphore)
            for tool, _, command in tasks
        ]
    )

    for (tool, raw_path, command), result in zip(tasks, results):
        raw_path.write_text(result.stdout, encoding="utf-8")
        chain.append(
            ChainRecord(
                stage="discovery",
                tool=tool,
                command=command,
                input_files=[target],
                output_files=[str(raw_path)],
                returncode=result.returncode,
                elapsed_ms=result.elapsed_ms,
                note=result.stderr.strip(),
            )
        )

    combined_raw = output_dir / "subdomains_raw.txt"
    merged_values: List[str] = []
    for raw_path in raw_files:
        merged_values.extend(read_lines(raw_path))
    write_lines(combined_raw, merged_values)

    cleaned_path = output_dir / "subdomains.txt"
    await sort_unique(combined_raw, cleaned_path, semaphore)
    chain.append(
        ChainRecord(
            stage="normalize",
            tool="sort",
            command=f"LC_ALL=C sort -u {shell_quote(str(combined_raw))} -o {shell_quote(str(cleaned_path))}",
            input_files=[str(p) for p in raw_files],
            output_files=[str(cleaned_path)],
            returncode=0,
            elapsed_ms=0,
            note="cleaned with sort -u",
        )
    )
    return cleaned_path


async def run_passive_recon(target: str, subdomains_file: Path, output_dir: Path, semaphore: asyncio.Semaphore, chain: List[ChainRecord]) -> Tuple[Path, List[str]]:
    outputs: List[str] = []

    for tool in PASSIVE_RECON_TOOLS:
        if not tool_available(tool):
            continue
        if tool == "httprobe":
            continue
        if tool == "dnsx":
            dnsx_output = output_dir / "dnsx_raw.txt"
            dnsx_command = f"dnsx -l {shell_quote(str(subdomains_file))} -resp -silent"
            dnsx_result = await run_tool_command("dnsx", dnsx_command, semaphore)
            dnsx_output.write_text(dnsx_result.stdout, encoding="utf-8")
            chain.append(
                ChainRecord(
                    stage="dns-validation",
                    tool="dnsx",
                    command=dnsx_command,
                    input_files=[str(subdomains_file)],
                    output_files=[str(dnsx_output)],
                    returncode=dnsx_result.returncode,
                    elapsed_ms=dnsx_result.elapsed_ms,
                    note=dnsx_result.stderr.strip(),
                )
            )
            continue

        output_path = output_dir / f"{tool}_raw.txt"
        command = build_passive_command(tool, target)
        result = await run_tool_command(tool, command, semaphore)
        output_path.write_text(result.stdout, encoding="utf-8")
        chain.append(
            ChainRecord(
                stage="passive-recon",
                tool=tool,
                command=command,
                input_files=[target],
                output_files=[str(output_path)],
                returncode=result.returncode,
                elapsed_ms=result.elapsed_ms,
                note=result.stderr.strip(),
            )
        )
        outputs.extend(read_lines(output_path))

    cleaned_path = output_dir / "passive_urls.txt"
    write_lines(cleaned_path, dedupe_lines(outputs))
    return cleaned_path, read_lines(cleaned_path)


async def run_crawler(live_urls: Sequence[str], output_dir: Path, semaphore: asyncio.Semaphore, chain: List[ChainRecord]) -> Tuple[Path, List[str]]:
    if not tool_available("katana") or not live_urls:
        return output_dir / "katana_urls.txt", []

    target_file = output_dir / "katana_targets.txt"
    write_lines(target_file, live_urls)
    output_path = output_dir / "katana_raw.txt"
    command = f"katana -list {shell_quote(str(target_file))} -silent"
    result = await run_tool_command("katana", command, semaphore)
    output_path.write_text(result.stdout, encoding="utf-8")
    chain.append(
        ChainRecord(
            stage="crawl",
            tool="katana",
            command=command,
            input_files=[str(target_file)],
            output_files=[str(output_path)],
            returncode=result.returncode,
            elapsed_ms=result.elapsed_ms,
            note=result.stderr.strip(),
        )
    )
    cleaned_path = output_dir / "katana_urls.txt"
    write_lines(cleaned_path, dedupe_lines(read_lines(output_path)))
    return cleaned_path, read_lines(cleaned_path)


async def run_extra_subdomain_sources(target: str, output_dir: Path, semaphore: asyncio.Semaphore, chain: List[ChainRecord]) -> Tuple[Path, List[str]]:
    sources: List[str] = []

    if tool_available("sublist3r"):
        output_path = output_dir / "sublist3r_raw.txt"
        command = f"sublist3r -d {shell_quote(target)} -o {shell_quote(str(output_path))}"
        result = await run_tool_command("sublist3r", command, semaphore)
        if output_path.exists():
            sources.extend(read_lines(output_path))
        elif result.stdout.strip():
            output_path.write_text(result.stdout, encoding="utf-8")
            sources.extend(read_lines(output_path))
        chain.append(
            ChainRecord(
                stage="discovery",
                tool="sublist3r",
                command=command,
                input_files=[target],
                output_files=[str(output_path)],
                returncode=result.returncode,
                elapsed_ms=result.elapsed_ms,
                note=result.stderr.strip(),
            )
        )

    cleaned_path = output_dir / "sublist3r_subdomains.txt"
    write_lines(cleaned_path, dedupe_lines(sources))
    return cleaned_path, read_lines(cleaned_path)


async def run_dns_checks(target: str, output_dir: Path, semaphore: asyncio.Semaphore, chain: List[ChainRecord]) -> List[str]:
    results: List[str] = []
    if not any(tool_available(name) for name in ("dig", "nslookup")):
        return results

    wildcard_candidate = f"aura-{int(time.time())}.{target}"
    output_path = output_dir / "dns_checks.txt"

    if tool_available("dig"):
        command = f"dig +short {shell_quote(target)} && dig +short {shell_quote(wildcard_candidate)}"
        result = await run_tool_command("dig", command, semaphore)
        output_path.write_text(result.stdout, encoding="utf-8")
        results.extend(read_lines(output_path))
        chain.append(
            ChainRecord(
                stage="dns-check",
                tool="dig",
                command=command,
                input_files=[target],
                output_files=[str(output_path)],
                returncode=result.returncode,
                elapsed_ms=result.elapsed_ms,
                note=result.stderr.strip(),
            )
        )

    if tool_available("nslookup"):
        nslookup_output = output_dir / "nslookup_checks.txt"
        command = f"nslookup {shell_quote(target)} && nslookup {shell_quote(wildcard_candidate)}"
        result = await run_tool_command("nslookup", command, semaphore)
        nslookup_output.write_text(result.stdout, encoding="utf-8")
        chain.append(
            ChainRecord(
                stage="dns-check",
                tool="nslookup",
                command=command,
                input_files=[target],
                output_files=[str(nslookup_output)],
                returncode=result.returncode,
                elapsed_ms=result.elapsed_ms,
                note=result.stderr.strip(),
            )
        )
        results.extend(read_lines(nslookup_output))

    return dedupe_lines(results)


async def run_httprobe(subdomains_file: Path, output_dir: Path, semaphore: asyncio.Semaphore, chain: List[ChainRecord]) -> Tuple[Path, List[str]]:
    if not tool_available("httprobe"):
        return output_dir / "httprobe.txt", []

    output_path = output_dir / "httprobe.txt"
    if sys.platform == "win32":
        command = f"type {shell_quote(str(subdomains_file))} | httprobe"
    else:
        command = f"cat {shell_quote(str(subdomains_file))} | httprobe"
    result = await run_tool_command("httprobe", command, semaphore)
    output_path.write_text(result.stdout, encoding="utf-8")
    chain.append(
        ChainRecord(
            stage="probe",
            tool="httprobe",
            command=command,
            input_files=[str(subdomains_file)],
            output_files=[str(output_path)],
            returncode=result.returncode,
            elapsed_ms=result.elapsed_ms,
            note=result.stderr.strip(),
        )
    )
    return output_path, read_lines(output_path)


async def run_whatweb(live_urls: Sequence[str], output_dir: Path, semaphore: asyncio.Semaphore, chain: List[ChainRecord]) -> Tuple[Path, List[str]]:
    if not tool_available("whatweb") or not live_urls:
        return output_dir / "whatweb.txt", []

    output_path = output_dir / "whatweb.txt"
    selected_urls = live_urls[: min(len(live_urls), 10)]
    command = "whatweb --no-errors --color=never " + " ".join(shell_quote(url) for url in selected_urls)
    result = await run_tool_command("whatweb", command, semaphore)
    output_path.write_text(result.stdout, encoding="utf-8")
    chain.append(
        ChainRecord(
            stage="fingerprint",
            tool="whatweb",
            command=command,
            input_files=list(selected_urls),
            output_files=[str(output_path)],
            returncode=result.returncode,
            elapsed_ms=result.elapsed_ms,
            note=result.stderr.strip(),
        )
    )
    return output_path, read_lines(output_path)


async def run_exploit_checks(candidate_urls: Sequence[str], output_dir: Path, semaphore: asyncio.Semaphore, full_scan: bool, chain: List[ChainRecord]) -> List[str]:
    if not candidate_urls:
        return []

    findings: List[str] = []
    targets = [url for url in candidate_urls if "?" in url][: 10 if full_scan else 3]
    for index, url in enumerate(targets, start=1):
        if tool_available("sqlmap"):
            sqlmap_output = output_dir / f"sqlmap_{index}.txt"
            command = f"sqlmap -u {shell_quote(url)} --batch --smart --level=1 --risk=1"
            result = await run_tool_command("sqlmap", command, semaphore)
            sqlmap_output.write_text(result.stdout, encoding="utf-8")
            chain.append(
                ChainRecord(
                    stage="exploit-check",
                    tool="sqlmap",
                    command=command,
                    input_files=[url],
                    output_files=[str(sqlmap_output)],
                    returncode=result.returncode,
                    elapsed_ms=result.elapsed_ms,
                    note=result.stderr.strip(),
                )
            )
            findings.extend(read_lines(sqlmap_output))

        if tool_available("commix"):
            commix_output = output_dir / f"commix_{index}.txt"
            command = f"commix --url={shell_quote(url)} --batch"
            result = await run_tool_command("commix", command, semaphore)
            commix_output.write_text(result.stdout, encoding="utf-8")
            chain.append(
                ChainRecord(
                    stage="exploit-check",
                    tool="commix",
                    command=command,
                    input_files=[url],
                    output_files=[str(commix_output)],
                    returncode=result.returncode,
                    elapsed_ms=result.elapsed_ms,
                    note=result.stderr.strip(),
                )
            )
            findings.extend(read_lines(commix_output))

    return dedupe_lines(findings)


def build_port_candidates(subdomains_file: Path, naabu_lines: List[str]) -> Dict[str, List[int]]:
    hosts = read_lines(subdomains_file)
    candidates: Dict[str, set[int]] = {host: set() for host in hosts}

    for line in naabu_lines:
        if ":" not in line:
            continue
        host, port_text = line.rsplit(":", 1)
        try:
            port = int(port_text)
        except ValueError:
            continue
        candidates.setdefault(host, set()).add(port)

    return {host: sorted(ports) for host, ports in candidates.items() if ports}


def common_port_list(full_scan: bool) -> List[int]:
    if full_scan:
        return list(range(1, 65536))
    return sorted(WEB_PORTS)


async def run_port_scan(subdomains_file: Path, output_dir: Path, semaphore: asyncio.Semaphore, threads: int, full_scan: bool, chain: List[ChainRecord]) -> Path:
    ports_file = output_dir / "ports.txt"

    if not tool_available("nmap") and not tool_available("naabu"):
        print("[!] Neither nmap nor naabu found; skipping port scan stage.")
        write_lines(ports_file, [])
        return ports_file

    raw_naabu = output_dir / "naabu_raw.txt"
    naabu_lines: List[str] = []

    if tool_available("naabu"):
        rate = max(50, threads * 200)
        naabu_command = f"naabu -list {shell_quote(str(subdomains_file))} -silent -rate {rate}"
        naabu_result = await run_tool_command("naabu", naabu_command, semaphore)
        raw_naabu.write_text(naabu_result.stdout, encoding="utf-8")
        naabu_lines = read_lines(raw_naabu)
        chain.append(
            ChainRecord(
                stage="port-discovery",
                tool="naabu",
                command=naabu_command,
                input_files=[str(subdomains_file)],
                output_files=[str(raw_naabu)],
                returncode=naabu_result.returncode,
                elapsed_ms=naabu_result.elapsed_ms,
                note=naabu_result.stderr.strip(),
            )
        )
    else:
        print("[!] naabu not found; using nmap for port discovery and service detection.")

    candidates = build_port_candidates(subdomains_file, naabu_lines)
    if candidates:
        port_list = sorted({port for ports in candidates.values() for port in ports})
        nmap_ports = ",".join(str(port) for port in port_list)
        nmap_command = f"nmap -sV -Pn -n -p {nmap_ports} -iL {shell_quote(str(subdomains_file))} -oX -"
    else:
        fallback_ports = common_port_list(full_scan)
        if full_scan:
            nmap_command = f"nmap -sV -Pn -n -p- -iL {shell_quote(str(subdomains_file))} -oX -"
        else:
            port_list = ",".join(str(port) for port in fallback_ports)
            nmap_command = f"nmap -sV -Pn -n -p {port_list} -iL {shell_quote(str(subdomains_file))} -oX -"

    nmap_result = await run_tool_command("nmap", nmap_command, semaphore)
    raw_nmap = output_dir / "nmap_raw.xml"
    raw_nmap.write_text(nmap_result.stdout, encoding="utf-8")
    chain.append(
        ChainRecord(
            stage="service-detection",
            tool="nmap",
            command=nmap_command,
            input_files=[str(subdomains_file)],
            output_files=[str(raw_nmap)],
            returncode=nmap_result.returncode,
            elapsed_ms=nmap_result.elapsed_ms,
            note=nmap_result.stderr.strip(),
        )
    )

    open_ports = parse_nmap_xml(nmap_result.stdout)
    if not open_ports and naabu_lines:
        for line in naabu_lines:
            if ":" not in line:
                continue
            host, port_text = line.rsplit(":", 1)
            try:
                port = int(port_text)
            except ValueError:
                continue
            open_ports.append(
                {
                    "target": host,
                    "address": host,
                    "protocol": "tcp",
                    "port": port,
                    "state": "open",
                    "reason": "naabu",
                    "service": {},
                }
            )

    normalized_ports = [
        "\t".join(
            [
                str(item.get("target", "")),
                str(item.get("address", "")),
                str(item.get("protocol", "tcp")),
                str(item.get("port", "")),
                str(item.get("state", "open")),
                json.dumps(item.get("service", {}), sort_keys=True),
            ]
        )
        for item in open_ports
    ]
    ports_path = output_dir / "ports.txt"
    write_lines(ports_path, normalized_ports)
    return ports_path


def build_httpx_targets(subdomains_file: Path, ports_file: Path, full_scan: bool, extra_urls: Sequence[str]) -> List[str]:
    targets: List[str] = []
    seen = set()

    for host in read_lines(subdomains_file):
        if host not in seen:
            targets.append(host)
            seen.add(host)

    for line in read_lines(ports_file):
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        host = parts[0]
        try:
            port = int(parts[3])
        except ValueError:
            continue
        if not full_scan and port not in WEB_PORTS:
            continue
        value = f"{host}:{port}"
        if value not in seen:
            targets.append(value)
            seen.add(value)

    for url in extra_urls:
        value = url.strip()
        if value and value not in seen:
            targets.append(value)
            seen.add(value)

    return targets


def build_full_url_set(*groups: Sequence[str]) -> List[str]:
    merged: List[str] = []
    for group in groups:
        merged.extend(group)
    return dedupe_lines(merged)


def build_methodology_status(output_dir: Path, request_file: Optional[str]) -> List[Dict[str, Any]]:
    return [
        {
            "phase": "1. Reconnaissance & Initial Enumeration",
            "status": "done",
            "artifacts": [
                str(output_dir / "subdomains.txt"),
                str(output_dir / "passive_urls.txt"),
                str(output_dir / "httprobe.txt"),
            ],
            "tools": ["subfinder", "assetfinder", "amass", "sublist3r", "gau", "waybackurls", "httprobe", "httpx"],
        },
        {
            "phase": "2. Authentication & Session Management",
            "status": "queued" if not request_file else "checked",
            "artifacts": [str(output_dir / "burp_like_lab.json") if request_file else ""],
            "tools": ["request-lab", "sqlmap", "commix"],
        },
        {
            "phase": "3. Business Logic Flaws",
            "status": "manual",
            "artifacts": [str(output_dir / "burp_like_lab.json") if request_file else ""],
            "tools": ["request-lab", "katana"],
        },
        {
            "phase": "4. Access Control Testing",
            "status": "manual",
            "artifacts": [str(output_dir / "burp_like_lab.json") if request_file else ""],
            "tools": ["request-lab"],
        },
        {
            "phase": "5. Input Validation & Injection",
            "status": "done" if Path(output_dir / "nuclei_raw.jsonl").exists() else "queued",
            "artifacts": [str(output_dir / "nuclei_raw.jsonl"), str(output_dir / "sqlmap_1.txt"), str(output_dir / "commix_1.txt")],
            "tools": ["ffuf", "nuclei", "sqlmap", "commix"],
        },
        {
            "phase": "6. API Security Testing",
            "status": "manual",
            "artifacts": [str(output_dir / "katana_urls.txt"), str(output_dir / "whatweb.txt")],
            "tools": ["katana", "whatweb", "httpx"],
        },
        {
            "phase": "7. Security Misconfigurations",
            "status": "done",
            "artifacts": [str(output_dir / "whatweb.txt"), str(output_dir / "dns_checks.txt")],
            "tools": ["whatweb", "dig", "nslookup", "nuclei"],
        },
        {
            "phase": "8. Manual & Advanced Techniques",
            "status": "manual",
            "artifacts": [str(output_dir / "burp_like_lab.json") if request_file else ""],
            "tools": ["request-lab", "katana", "ffuf", "sqlmap", "commix"],
        },
        {
            "phase": "9. Reporting",
            "status": "done",
            "artifacts": [str(output_dir / "vulns.json")],
            "tools": ["json-report"],
        },
    ]


async def run_httpx(targets: Sequence[str], output_dir: Path, semaphore: asyncio.Semaphore, threads: int, chain: List[ChainRecord]) -> Tuple[Path, List[Dict[str, Any]]]:
    if not tool_available("httpx"):
        raise SystemExit("httpx is required for live web probing and is not installed.")

    target_file = output_dir / "httpx_targets.txt"
    write_lines(target_file, targets)
    raw_output = output_dir / "httpx_raw.jsonl"
    if not targets:
        write_lines(raw_output, [])
        return raw_output, []

    command = (
        f"httpx -l {shell_quote(str(target_file))} -json -status-code -title -tech-detect "
        f"-follow-redirects -no-color -threads {max(1, threads)}"
    )
    result = await run_tool_command("httpx", command, semaphore)
    raw_output.write_text(result.stdout, encoding="utf-8")
    chain.append(
        ChainRecord(
            stage="probe",
            tool="httpx",
            command=command,
            input_files=[str(target_file)],
            output_files=[str(raw_output)],
            returncode=result.returncode,
            elapsed_ms=result.elapsed_ms,
            note=result.stderr.strip(),
        )
    )
    return raw_output, parse_httpx_json_lines(result.stdout)


async def run_ffuf(live_targets: Sequence[str], output_dir: Path, semaphore: asyncio.Semaphore, threads: int, full_scan: bool, wordlist: str, chain: List[ChainRecord]) -> List[Dict[str, Any]]:
    if not tool_available("ffuf"):
        print("[!] ffuf not found; skipping directory fuzzing stage.")
        return []

    if not Path(wordlist).exists():
        print(f"[!] Wordlist not found at {wordlist}; skipping directory fuzzing stage.")
        return []

    targets = list(live_targets)
    if not full_scan:
        targets = targets[: min(5, len(targets))]

    findings: List[Dict[str, Any]] = []
    tasks = []
    for index, url in enumerate(targets, start=1):
        output_path = output_dir / f"ffuf_{index}.json"
        command = (
            f"ffuf -u {shell_quote(url.rstrip('/') + '/FUZZ')} -w {shell_quote(wordlist)} "
            f"-of json -o {shell_quote(str(output_path))} -t {max(1, threads)} -ac "
            f"-mc 200,204,301,302,307,401,403,405,500"
        )
        if full_scan:
            command += " -recursion -recursion-depth 2"
        tasks.append((url, output_path, command))

    results = await asyncio.gather(*[run_tool_command("ffuf", command, semaphore) for _, _, command in tasks])
    for (url, output_path, command), result in zip(tasks, results):
        if not output_path.exists() and result.stdout.strip():
            output_path.write_text(result.stdout, encoding="utf-8")
        chain.append(
            ChainRecord(
                stage="fuzz",
                tool="ffuf",
                command=command,
                input_files=[url],
                output_files=[str(output_path)],
                returncode=result.returncode,
                elapsed_ms=result.elapsed_ms,
                note=result.stderr.strip(),
            )
        )
        findings.extend(parse_ffuf_json(output_path))

    return findings


async def run_nuclei(live_targets: Sequence[str], output_dir: Path, semaphore: asyncio.Semaphore, threads: int, templates: Optional[str], chain: List[ChainRecord]) -> List[Dict[str, Any]]:
    if not tool_available("nuclei"):
        print("[!] nuclei not found; skipping vulnerability scan stage.")
        return []

    if templates and not Path(templates).exists():
        raise SystemExit(
            f"Nuclei template path not found: {templates}\n"
            "Install the nuclei templates repository, or pass an existing --templates path.\n"
            "Example: git clone https://github.com/projectdiscovery/nuclei-templates"
        )

    target_file = output_dir / "nuclei_targets.txt"
    write_lines(target_file, live_targets)
    if not live_targets:
        return []

    nuclei_output = output_dir / "nuclei_raw.jsonl"
    command = (
        f"nuclei -l {shell_quote(str(target_file))} -json -silent -severity low,medium,high,critical "
        f"-c {max(1, threads)}"
    )
    if templates:
        command += f" -t {shell_quote(templates)}"

    result = await run_tool_command("nuclei", command, semaphore)
    nuclei_output.write_text(result.stdout, encoding="utf-8")
    chain.append(
        ChainRecord(
            stage="vulnerability-scan",
            tool="nuclei",
            command=command,
            input_files=[str(target_file)],
            output_files=[str(nuclei_output)],
            returncode=result.returncode,
            elapsed_ms=result.elapsed_ms,
            note=result.stderr.strip(),
        )
    )

    findings: List[Dict[str, Any]] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return findings


def build_vuln_report(
    target: str,
    output_dir: Path,
    subdomains_file: Path,
    ports_file: Path,
    httpx_records: List[Dict[str, Any]],
    ffuf_records: List[Dict[str, Any]],
    nuclei_records: List[Dict[str, Any]],
    chain: List[ChainRecord],
    *,
    threads: int,
    full_scan: bool,
    wordlist: str,
    templates: Optional[str],
    request_file: Optional[str],
) -> Path:
    report = {
        "target": target,
        "generated_at_unix": time.time(),
        "settings": {
            "threads": threads,
            "full_scan": full_scan,
            "wordlist": wordlist,
            "templates": templates,
        },
        "counts": {
            "subdomains": len(read_lines(subdomains_file)),
            "extra_subdomains": len(read_lines(output_dir / "sublist3r_subdomains.txt")),
            "dns_checks": len(read_lines(output_dir / "dns_checks.txt")) + len(read_lines(output_dir / "nslookup_checks.txt")),
            "passive_urls": len(read_lines(output_dir / "passive_urls.txt")),
            "ports": len(read_lines(ports_file)),
            "live_targets": len(httpx_records),
            "httprobe_targets": len(read_lines(output_dir / "httprobe.txt")),
            "fingerprints": len(read_lines(output_dir / "whatweb.txt")),
            "crawled_urls": len(read_lines(output_dir / "katana_urls.txt")),
            "ffuf_findings": len(ffuf_records),
            "nuclei_findings": len(nuclei_records),
            "exploit_notes": len(read_lines(output_dir / "sqlmap_1.txt")) + len(read_lines(output_dir / "commix_1.txt")),
        },
        "findings": {
            "httpx": httpx_records,
            "ffuf": ffuf_records,
            "nuclei": nuclei_records,
        },
        "methodology": build_methodology_status(output_dir, request_file),
        "chain_of_custody": [asdict(item) for item in chain],
    }
    report_path = output_dir / "vulns.json"
    write_json(report_path, report)
    return report_path


async def run_pipeline(args: argparse.Namespace) -> int:
    if not args.authorized:
        raise SystemExit("Safety check failed: pass --authorized only for explicitly approved bug bounty scope targets.")

    target_slug = sanitize_target(args.target)
    output_dir = Path(args.output_dir) / target_slug
    output_dir.mkdir(parents=True, exist_ok=True)

    semaphore = asyncio.Semaphore(max(1, args.threads))
    chain: List[ChainRecord] = []

    await preflight_tools(semaphore)

    if args.lab_only and not args.request_file:
        raise SystemExit("--lab-only requires --request-file")

    if args.request_file and args.lab_only:
        lab_output = await asyncio.to_thread(run_request_lab, Path(args.request_file), output_dir)
        print(f"[+] Burp-like lab output: {lab_output}")
        return 0

    subdomains_file = await run_discovery(args.target, output_dir, semaphore, args.full_scan, chain)
    if not read_lines(subdomains_file):
        raise SystemExit(f"No subdomains discovered for {args.target}.")

    extra_subdomains_file, extra_subdomains = await run_extra_subdomain_sources(args.target, output_dir, semaphore, chain)
    merged_subdomains = build_full_url_set(read_lines(subdomains_file), read_lines(extra_subdomains_file))
    write_lines(subdomains_file, merged_subdomains)

    dns_notes = await run_dns_checks(args.target, output_dir, semaphore, chain)

    passive_urls_file, passive_urls = await run_passive_recon(args.target, subdomains_file, output_dir, semaphore, chain)
    httprobe_file, httprobe_urls = await run_httprobe(subdomains_file, output_dir, semaphore, chain)

    ports_file = await run_port_scan(subdomains_file, output_dir, semaphore, args.threads, args.full_scan, chain)

    httpx_targets = build_httpx_targets(subdomains_file, ports_file, args.full_scan, build_full_url_set(passive_urls, httprobe_urls, dns_notes))
    httpx_raw, httpx_records = await run_httpx(httpx_targets, output_dir, semaphore, args.threads, chain)

    live_urls = list(dict.fromkeys(record.get("url") for record in httpx_records if record.get("url")))

    whatweb_file, whatweb_output = await run_whatweb(live_urls, output_dir, semaphore, chain)
    katana_urls_file, katana_urls = await run_crawler(live_urls, output_dir, semaphore, chain)
    nuclei_targets = build_full_url_set(live_urls, katana_urls, read_lines(passive_urls_file), read_lines(whatweb_file))

    ffuf_records = await run_ffuf(live_urls, output_dir, semaphore, args.threads, args.full_scan, args.wordlist, chain)
    nuclei_records = await run_nuclei(nuclei_targets, output_dir, semaphore, args.threads, args.templates, chain)
    exploit_notes = await run_exploit_checks(nuclei_targets, output_dir, semaphore, args.full_scan, chain)

    if args.request_file:
        lab_output = await asyncio.to_thread(run_request_lab, Path(args.request_file), output_dir)
        print(f"[+] Burp-like lab output: {lab_output}")

    build_vuln_report(
        args.target,
        output_dir,
        subdomains_file,
        ports_file,
        httpx_records,
        ffuf_records,
        nuclei_records,
        chain,
        threads=args.threads,
        full_scan=args.full_scan,
        wordlist=args.wordlist,
        templates=args.templates,
        request_file=args.request_file,
    )

    print(f"[+] Results saved to: {output_dir}")
    print(f"[+] Subdomains: {subdomains_file}")
    print(f"[+] Ports: {ports_file}")
    print(f"[+] Probing output: {httpx_raw}")
    print(f"[+] WhatWeb output: {whatweb_file}")
    print(f"[+] HTTP probe output: {httprobe_file}")
    print(f"[+] Vulnerability report: {output_dir / 'vulns.json'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AURA-RECON - async bug bounty recon orchestrator")
    parser.add_argument("--target", default="", help="Target domain, for example example.com")
    parser.add_argument("--threads", type=int, default=4, help="Concurrency limit for subprocesses and scanners")
    parser.add_argument("--full-scan", action="store_true", help="Run deeper scans and broader fuzzing")
    parser.add_argument("--output-dir", default="results", help="Base directory for per-target results")
    parser.add_argument("--wordlist", default=DEFAULT_WORDLIST, help="Wordlist for ffuf")
    parser.add_argument("--templates", help="Optional nuclei template path; omit to use nuclei defaults")
    parser.add_argument("--request-file", help="Raw HTTP request file for Burp-like replay and mutation testing")
    parser.add_argument("--lab-only", action="store_true", help="Run only the Burp-like request lab using --request-file")
    parser.add_argument("--check-tools", action="store_true", help="Only run the tool preflight check and exit")
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Required safety flag confirming the target is in your approved bug bounty scope",
    )
    return parser


def main() -> None:
    banner()
    parser = build_parser()
    args = parser.parse_args()

    # --check-tools does not require --target
    if args.check_tools:
        if sys.platform == "win32":
            # suppress asyncio ResourceWarning noise on Windows
            import warnings
            warnings.filterwarnings("ignore", category=ResourceWarning)
        try:
            asyncio.run(preflight_tools(asyncio.Semaphore(max(1, args.threads))))
        except SystemExit:
            pass
        return

    if not args.target:
        parser.error("--target is required unless --check-tools is used")

    if sys.platform == "win32":
        import warnings
        warnings.filterwarnings("ignore", category=ResourceWarning)

    try:
        raise SystemExit(asyncio.run(run_pipeline(args)))
    except KeyboardInterrupt:
        raise SystemExit(130)


if __name__ == "__main__":
    main()

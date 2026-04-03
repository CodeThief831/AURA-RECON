from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests


@dataclass
class RawHttpRequest:
    method: str
    url: str
    headers: Dict[str, str]
    body: str


@dataclass
class LabFinding:
    test: str
    url: str
    title: str
    severity: str
    confidence: str
    summary: str
    evidence: List[str] = field(default_factory=list)
    remediation: str = ""


@dataclass
class LabResult:
    request: RawHttpRequest
    status_code: int
    response_headers: Dict[str, str]
    body: str
    elapsed_ms: int
    findings: List[LabFinding]


COMMON_JSON_MARKERS = {
    "string": "AURA-LAB-STRING",
    "number": 1337,
    "null": None,
    "bool": True,
}

COMMON_HEADER_MUTATIONS = [
    "Origin",
    "Referer",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Real-IP",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-HTTP-Method-Override",
    "User-Agent",
]


def parse_raw_http_request(raw_text: str) -> RawHttpRequest:
    lines = raw_text.splitlines()
    if not lines:
        raise ValueError("Raw request is empty")

    request_line = lines[0].strip()
    match = re.match(r"^(\S+)\s+(\S+)\s+HTTP/\d(?:\.\d)?$", request_line)
    if not match:
        raise ValueError("Invalid request line")

    method, path = match.group(1), match.group(2)
    headers: Dict[str, str] = {}
    body_lines: List[str] = []
    in_body = False
    for line in lines[1:]:
        if not in_body and not line.strip():
            in_body = True
            continue
        if in_body:
            body_lines.append(line)
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip()] = value.strip()

    host = headers.get("Host") or headers.get("host")
    if not host:
        raise ValueError("Missing Host header")

    scheme = headers.get("X-Forwarded-Proto") or "https"
    if path.startswith("http://") or path.startswith("https://"):
        url = path
    else:
        url = f"{scheme}://{host}{path}"

    return RawHttpRequest(method=method.upper(), url=url, headers=headers, body="\n".join(body_lines))


def _normalize_response_headers(headers: requests.structures.CaseInsensitiveDict) -> Dict[str, str]:
    return {key: value for key, value in headers.items()}


def send_request(parsed: RawHttpRequest, override_headers: Optional[Dict[str, str]] = None, override_body: Optional[str] = None) -> Tuple[int, Dict[str, str], str, int]:
    headers = dict(parsed.headers)
    if override_headers:
        headers.update(override_headers)
    headers.pop("Content-Length", None)

    body = parsed.body if override_body is None else override_body
    data: Optional[bytes]
    if body:
        data = body.encode("utf-8")
    else:
        data = None

    try:
        response = requests.request(
            method=parsed.method,
            url=parsed.url,
            headers=headers,
            data=data,
            timeout=15,
            allow_redirects=False,
        )
        elapsed_ms = int(response.elapsed.total_seconds() * 1000)
        return response.status_code, _normalize_response_headers(response.headers), response.text, elapsed_ms
    except requests.RequestException as exc:
        return 0, {}, str(exc), 0


def analyze_session_headers(response_headers: Dict[str, str]) -> List[LabFinding]:
    findings: List[LabFinding] = []
    cookies = [value for key, value in response_headers.items() if key.lower() == "set-cookie"]
    for cookie in cookies:
        lower = cookie.lower()
        missing = []
        if "httponly" not in lower:
            missing.append("HttpOnly")
        if "secure" not in lower:
            missing.append("Secure")
        if "samesite" not in lower:
            missing.append("SameSite")
        if missing:
            findings.append(
                LabFinding(
                    test="session-cookie-flags",
                    url="",
                    title="Session cookie missing expected security flags",
                    severity="medium",
                    confidence="high",
                    summary="A returned cookie does not include all recommended security flags.",
                    evidence=[cookie, "Missing: " + ", ".join(missing)],
                    remediation="Set HttpOnly, Secure, and SameSite on sensitive cookies where applicable.",
                )
            )
    return findings


def analyze_cors(parsed: RawHttpRequest) -> List[LabFinding]:
    findings: List[LabFinding] = []
    cors_headers = {"Origin": "https://evil.example"}
    status_code, response_headers, body, _ = send_request(parsed, override_headers=cors_headers)
    _ = body

    acao = response_headers.get("Access-Control-Allow-Origin", "")
    acac = response_headers.get("Access-Control-Allow-Credentials", "")
    if acao == "*" and acac.lower() == "true":
        findings.append(
            LabFinding(
                test="cors-misconfiguration",
                url=parsed.url,
                title="Potential CORS misconfiguration",
                severity="medium",
                confidence="high",
                summary="The response reflects an overly permissive CORS policy.",
                evidence=[f"Status: {status_code}", f"Access-Control-Allow-Origin: {acao}", f"Access-Control-Allow-Credentials: {acac}"],
                remediation="Restrict allowed origins to trusted domains and avoid wildcard origins with credentials.",
            )
        )
    return findings


def mutate_query_params(parsed: RawHttpRequest) -> List[RawHttpRequest]:
    parsed_url = urlparse(parsed.url)
    params = parse_qsl(parsed_url.query, keep_blank_values=True)
    if not params:
        return []

    mutated: List[RawHttpRequest] = []
    for index, (name, value) in enumerate(params):
        new_params = list(params)
        new_params[index] = (name, "AURA-LAB-QP")
        new_query = urlencode(new_params, doseq=True)
        new_url = urlunparse(parsed_url._replace(query=new_query))
        mutated.append(RawHttpRequest(method=parsed.method, url=new_url, headers=dict(parsed.headers), body=parsed.body))
    return mutated


def mutate_json_body(parsed: RawHttpRequest) -> List[RawHttpRequest]:
    content_type = parsed.headers.get("Content-Type", parsed.headers.get("content-type", ""))
    if "application/json" not in content_type.lower():
        return []

    try:
        payload = json.loads(parsed.body or "{}")
    except json.JSONDecodeError:
        return []

    if not isinstance(payload, dict):
        return []

    mutated: List[RawHttpRequest] = []
    for key in payload.keys():
        for marker in COMMON_JSON_MARKERS.values():
            copied = dict(payload)
            copied[key] = marker
            mutated.append(
                RawHttpRequest(
                    method=parsed.method,
                    url=parsed.url,
                    headers=dict(parsed.headers),
                    body=json.dumps(copied),
                )
            )
    return mutated


def mutate_headers(parsed: RawHttpRequest) -> List[RawHttpRequest]:
    mutated: List[RawHttpRequest] = []
    for header_name in COMMON_HEADER_MUTATIONS:
        headers = dict(parsed.headers)
        headers[header_name] = "AURA-LAB-HEADER"
        mutated.append(RawHttpRequest(method=parsed.method, url=parsed.url, headers=headers, body=parsed.body))
    return mutated


def analyze_reflection(base_response: str, test_response: str, marker: str, title: str, test_name: str, url: str) -> Optional[LabFinding]:
    if marker in test_response and marker not in base_response:
        return LabFinding(
            test=test_name,
            url=url,
            title=title,
            severity="medium",
            confidence="medium",
            summary="A marker value is reflected in the response and may be exploitable depending on context.",
            evidence=[f"Marker: {marker}"],
            remediation="Validate and encode user-controlled data before rendering it in HTML, JSON, or JS contexts.",
        )
    return None


def run_request_lab(raw_request_file: Path, output_dir: Path) -> Path:
    parsed = parse_raw_http_request(raw_request_file.read_text(encoding="utf-8", errors="replace"))
    status_code, response_headers, body, elapsed_ms = send_request(parsed)

    findings: List[LabFinding] = []
    findings.extend(analyze_session_headers(response_headers))
    findings.extend(analyze_cors(parsed))

    base_response = body
    for mutated_request in mutate_query_params(parsed):
        status, _, mutated_body, _ = send_request(mutated_request)
        finding = analyze_reflection(base_response, mutated_body, "AURA-LAB-QP", "Potential reflected input issue", "query-param-fuzz", mutated_request.url)
        if finding:
            finding.evidence.append(f"Status: {status}")
            findings.append(finding)

    for mutated_request in mutate_json_body(parsed):
        status, _, mutated_body, _ = send_request(mutated_request)
        finding = analyze_reflection(base_response, mutated_body, "AURA-LAB-STRING", "Potential JSON reflection issue", "json-body-fuzz", mutated_request.url)
        if finding:
            finding.evidence.append(f"Status: {status}")
            findings.append(finding)

    for mutated_request in mutate_headers(parsed):
        status, mutated_headers, mutated_body, _ = send_request(mutated_request)
        finding = analyze_reflection(base_response, mutated_body, "AURA-LAB-HEADER", "Potential header reflection issue", "header-fuzz", mutated_request.url)
        if finding:
            finding.evidence.append(f"Status: {status}")
            findings.append(finding)
        if "Access-Control-Allow-Origin" in mutated_headers:
            acao = mutated_headers.get("Access-Control-Allow-Origin", "")
            if acao in {"*", mutated_request.headers.get("Origin", "")}:
                findings.append(
                    LabFinding(
                        test="cors-header-manual",
                        url=mutated_request.url,
                        title="Possible CORS policy weakness",
                        severity="medium",
                        confidence="medium",
                        summary="The response exposes CORS headers after header mutation.",
                        evidence=[f"Status: {status}", f"Access-Control-Allow-Origin: {acao}"],
                        remediation="Restrict CORS policies and avoid reflecting untrusted origins.",
                    )
                )

    payload = {
        "request": asdict(parsed),
        "baseline": {
            "status_code": status_code,
            "response_headers": response_headers,
            "elapsed_ms": elapsed_ms,
        },
        "findings": [asdict(item) for item in findings],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "burp_like_lab.json"
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return output_path

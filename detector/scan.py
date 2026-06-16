import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime

import requests
from dotenv import load_dotenv

load_dotenv()
sys.stdout.reconfigure(encoding="utf-8")

from crawl.poc_capture import run_crawl
from .payloads import (
    BOOLEAN_STRING_AND,
    BOOLEAN_STRING_OR,
    ERROR_BASED_PAYLOADS,
    TIME_BASED_PAYLOADS,
    render,
)
from .judge import (
    judge_boolean_sqli,
    judge_error_based_sqli,
    judge_time_based_sqli,
    SqliVerdict,
)

SKIP_PARAM_NAMES = {
    "submit", "btn_submit", "btn", "button", "save", "cancel", "ok", "reset", "send",
}
CSRF_RE = re.compile(r"(csrf|token|nonce|_token|authenticity|captcha)", re.IGNORECASE)
SESSION_COOKIE_NAMES = {"phpsessid", "jsessionid", "asp.net_sessionid"}

TIMEOUT = 10
TIME_BASED_REPEAT = 2


@dataclass
class Candidate:
    method: str
    base_url: str
    target_param: str
    base_value: str
    other_params: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)


def _is_skippable(name: str) -> bool:
    if name.lower() in SKIP_PARAM_NAMES:
        return True
    if CSRF_RE.search(name):
        return True
    return False


def load_candidates(jsonl_path: str) -> list[Candidate]:
    seen_structures: set[tuple] = set()
    candidates: list[Candidate] = []

    with open(jsonl_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)

            method = record.get("method", "GET").upper()
            base_url = record.get("base_url", "")
            params = record.get("parameters", [])
            cookies = record.get("cookies", {})

            param_names = tuple(sorted(p["name"] for p in params if p.get("name")))
            structure_key = (method, base_url, param_names)
            if structure_key in seen_structures:
                continue
            seen_structures.add(structure_key)

            all_values = {p["name"]: p.get("value", "") for p in params if p.get("name")}

            for p in params:
                name = p.get("name", "")
                if not name or _is_skippable(name):
                    continue
                other = {k: v for k, v in all_values.items() if k != name}
                candidates.append(Candidate(
                    method=method,
                    base_url=base_url,
                    target_param=name,
                    base_value=p.get("value", ""),
                    other_params=other,
                    cookies=cookies,
                ))

    return candidates


def _send(method: str, url: str, params: dict, cookies: dict) -> tuple[str, float]:
    session = requests.Session()
    session.cookies.update(cookies)
    started = time.perf_counter()
    if method == "POST":
        resp = session.post(url, data=params, timeout=TIMEOUT, allow_redirects=True)
    else:
        resp = session.get(url, params=params, timeout=TIMEOUT, allow_redirects=True)
    elapsed = time.perf_counter() - started
    return resp.text, elapsed


def _params_with(c: Candidate, value: str) -> dict:
    return {**c.other_params, c.target_param: value}


def _location_of(c: Candidate) -> str:
    return "query" if c.method == "GET" else "body"


def _to_finding(c: Candidate, request_id: str, category: str, payload: str, verdict: SqliVerdict) -> dict:
    return {
        "request_id": request_id,
        "method": c.method,
        "base_url": c.base_url,
        "target_param": c.target_param,
        "location": _location_of(c),
        "base_value": c.base_value,
        "vuln_type": "sqli",
        "category": category,
        "payload": payload,
        "confidence": verdict.confidence,
        "evidence": verdict.evidence,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
    }


def scan_candidate(c: Candidate, request_id: str) -> list[dict]:
    findings: list[dict] = []

    baseline_body, baseline_elapsed = _send(c.method, c.base_url, _params_with(c, c.base_value), c.cookies)

    and_true_payload = render(BOOLEAN_STRING_AND["true_payload"], c.base_value)
    and_false_payload = render(BOOLEAN_STRING_AND["false_payload"], c.base_value)
    or_true_payload = render(BOOLEAN_STRING_OR["true_payload"], c.base_value)
    and_true_body, _ = _send(c.method, c.base_url, _params_with(c, and_true_payload), c.cookies)
    and_false_body, _ = _send(c.method, c.base_url, _params_with(c, and_false_payload), c.cookies)
    or_true_body, _ = _send(c.method, c.base_url, _params_with(c, or_true_payload), c.cookies)
    verdict = judge_boolean_sqli(
        baseline_body, and_true_body, and_false_body, or_true_body,
        c.base_value, and_true_payload, and_false_payload, or_true_payload,
    )
    if verdict.vulnerable:
        if "AND 패턴" in verdict.evidence:
            category, payload = BOOLEAN_STRING_AND["family"], and_true_payload
        elif "OR 패턴" in verdict.evidence:
            category, payload = BOOLEAN_STRING_OR["family"], or_true_payload
        else:
            category, payload = "boolean_unknown", and_true_payload
        findings.append(_to_finding(c, request_id, category, payload, verdict))

    for p in ERROR_BASED_PAYLOADS:
        payload = render(p, c.base_value)
        attack_body, _ = _send(c.method, c.base_url, _params_with(c, payload), c.cookies)
        verdict = judge_error_based_sqli(baseline_body, attack_body)
        if verdict.vulnerable:
            findings.append(_to_finding(c, request_id, "error_based", payload, verdict))
            break

    time_payload = TIME_BASED_PAYLOADS[0]
    rendered = render(time_payload, c.base_value)
    elapsed_list = []
    for _ in range(TIME_BASED_REPEAT):
        _, e = _send(c.method, c.base_url, _params_with(c, rendered), c.cookies)
        elapsed_list.append(e)
    verdict = judge_time_based_sqli(baseline_elapsed, elapsed_list)
    if verdict.vulnerable:
        findings.append(_to_finding(c, request_id, "time_based", rendered, verdict))

    return findings


def main() -> None:
    if len(sys.argv) > 1:
        jsonl_path = sys.argv[1]
        print(f"[detector] 기존 run 재사용: {jsonl_path}")
    else:
        crawl_result_path = run_crawl()
        jsonl_path = os.path.join(os.path.dirname(crawl_result_path), "captured_requests.jsonl")
        print(f"[detector] 크롤링 완료: {jsonl_path}")

    candidates = load_candidates(jsonl_path)
    print(f"[detector] {len(candidates)}개 후보 파라미터")

    all_findings: list[dict] = []
    for i, c in enumerate(candidates, 1):
        request_id = f"req-{i:03d}"
        print(f"[{i}/{len(candidates)}] {c.method} {c.base_url} param={c.target_param}")
        try:
            findings = scan_candidate(c, request_id)
        except Exception as exc:
            print(f"  [ERROR] {exc}")
            continue
        for f in findings:
            print(f"  -> {f['category']} confidence={f['confidence']} {f['evidence']}")
        all_findings.extend(findings)

    out_path = os.path.join(os.path.dirname(jsonl_path), "findings.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(all_findings, f, ensure_ascii=False, indent=2)
    print(f"[detector] {len(all_findings)}개 발견, 저장: {out_path}")


if __name__ == "__main__":
    main()

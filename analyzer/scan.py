import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from difflib import SequenceMatcher
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()
sys.stdout.reconfigure(encoding="utf-8")

from crawl.run_crawl_session import run_crawl_session
from scanner.merge import merge
from authentication.auth import get_demo_dvwa_cookies
from utilities.file_utils import save_json
from .sqli.payloads import (
    BOOLEAN_STRING_AND,
    BOOLEAN_STRING_OR,
    BOOLEAN_NUMERIC_AND,
    BOOLEAN_NUMERIC_OR,
    BOOLEAN_STRING_AND_HASH,
    BOOLEAN_STRING_OR_HASH,
    BOOLEAN_NUMERIC_AND_HASH,
    BOOLEAN_NUMERIC_OR_HASH,
    BOOLEAN_ORDERBY,
    ERROR_BASED_PAYLOADS,
    UNION_PAYLOADS,
    TIME_BASED_PAYLOADS,
    render,
)
from .sqli.judge import (
    judge_boolean_sqli,
    judge_error_based_sqli,
    judge_union_sqli,
    judge_expression_sqli,
    judge_time_based_sqli,
    _strip_value,
)
from .xss.payloads import XSS_PAYLOADS
from .xss.judge import judge_xss

CSRF_RE = re.compile(r"(csrf|token|nonce|_token|authenticity|captcha)", re.IGNORECASE)

TIMEOUT = 10
TIME_BASED_REPEAT = 2

# ORDER BY 컨텍스트로 판단할 파라미터 이름 키워드
_ORDERBY_KEYWORDS = {"sort", "order", "orderby", "sortby", "col", "column", "dir", "direction"}
# 로그인 폼 파라미터 키워드 — boolean auth bypass 제외, error/time만 시도
_LOGIN_KEYWORDS   = {"username", "password", "user", "pass", "email", "login", "passwd", "pwd"}


def _is_orderby_param(name: str) -> bool:
    n = name.lower()
    return n in _ORDERBY_KEYWORDS or any(kw in n for kw in _ORDERBY_KEYWORDS)


def _is_login_param(name: str) -> bool:
    n = name.lower()
    return any(kw in n for kw in _LOGIN_KEYWORDS)


def _is_numeric(value: str) -> bool:
    try:
        int(value)
        return True
    except (ValueError, TypeError):
        return False


@dataclass
class Candidate:
    method: str
    base_url: str
    target_param: str
    base_value: str
    other_params: dict = field(default_factory=dict)


def load_candidates(scan_targets: list[dict]) -> list[Candidate]:
    candidates: list[Candidate] = []

    for target in scan_targets:
        if not target.get("can_scan", True):
            continue

        method = target.get("method", "GET").upper()
        base_url = target.get("base_url", "")
        parameters = target.get("parameters", [])

        # 파라미터 이름 → 대표값 매핑 (request context용)
        all_values = {
            p["name"]: (p["sample_values"][0] if p.get("sample_values") else "")
            for p in parameters
            if p.get("name")
        }

        for param in parameters:
            if not param.get("scan", True):
                continue
            name = param.get("name", "")
            if not name:
                continue
            base_value = param["sample_values"][0] if param.get("sample_values") else ""
            other = {k: v for k, v in all_values.items() if k != name}
            candidates.append(Candidate(
                method=method,
                base_url=base_url,
                target_param=name,
                base_value=base_value,
                other_params=other,
            ))

    return candidates


def _send(method: str, url: str, params: dict, session: requests.Session) -> tuple[str, float]:
    started = time.perf_counter()
    if method == "POST":
        resp = session.post(url, data=params, timeout=TIMEOUT, allow_redirects=True)
    else:
        resp = session.get(url, params=params, timeout=TIMEOUT, allow_redirects=True)
    elapsed = time.perf_counter() - started
    return resp.text, elapsed


def _refresh_csrf_tokens(session: requests.Session, c: Candidate) -> dict:
    try:
        resp = session.get(c.base_url, timeout=TIMEOUT)
        fresh = dict(c.other_params)
        for m in re.finditer(r'<input[^>]+>', resp.text, re.IGNORECASE):
            tag = m.group(0)
            name_m = re.search(r'name=["\']([^"\']+)["\']', tag, re.IGNORECASE)
            value_m = re.search(r'value=["\']([^"\']*)["\']', tag, re.IGNORECASE)
            if name_m:
                name = name_m.group(1)
                if name in fresh and CSRF_RE.search(name):
                    fresh[name] = value_m.group(1) if value_m else ""
        return fresh
    except Exception:
        return dict(c.other_params)


def _location_of(c: Candidate) -> str:
    return "query" if c.method == "GET" else "body"


def _to_finding(c: Candidate, request_id: str, vuln_type: str, category: str, payload: str, confidence: str, evidence: str) -> dict:
    return {
        "request_id": request_id,
        "method": c.method,
        "base_url": c.base_url,
        "target_param": c.target_param,
        "location": _location_of(c),
        "base_value": c.base_value,
        "vuln_type": vuln_type,
        "category": category,
        "payload": payload,
        "confidence": confidence,
        "evidence": evidence,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
    }


def _scan_sqli(c: Candidate, request_id: str, scan_cookies: dict) -> list[dict]:
    findings: list[dict] = []
    session = requests.Session()
    session.cookies.update(scan_cookies)
    fresh_other = _refresh_csrf_tokens(session, c) if c.method == "POST" else c.other_params

    def p(value: str) -> dict:
        return {**fresh_other, c.target_param: value}

    baseline_body, baseline_elapsed = _send(c.method, c.base_url, p(c.base_value), session)
    baseline2_body, _ = _send(c.method, c.base_url, p(c.base_value), session)
    b1_clean = _strip_value(baseline_body, c.base_value)
    b2_clean = _strip_value(baseline2_body, c.base_value)
    base_ratio = SequenceMatcher(None, b1_clean, b2_clean).ratio()

    # ORDER BY 컨텍스트: sort/order 류 파라미터는 CASE WHEN 방식으로 별도 탐지
    if _is_orderby_param(c.target_param):
        ob_true_payload  = render(BOOLEAN_ORDERBY["true_payload"],  c.base_value)
        ob_false_payload = render(BOOLEAN_ORDERBY["false_payload"], c.base_value)
        ob_true_body,  _ = _send(c.method, c.base_url, p(ob_true_payload),  session)
        ob_false_body, _ = _send(c.method, c.base_url, p(ob_false_payload), session)
        ob_true_clean  = _strip_value(ob_true_body,  ob_true_payload)
        ob_false_clean = _strip_value(ob_false_body, ob_false_payload)
        floor = 1.0 if base_ratio == 1.0 else base_ratio - 0.05
        if SequenceMatcher(None, ob_true_clean, ob_false_clean).ratio() < floor:
            findings.append(_to_finding(
                c, request_id, "sqli", BOOLEAN_ORDERBY["family"], ob_true_payload,
                "medium", f"Boolean SQLi (ORDER BY 패턴): CASE WHEN true≠false (floor={floor:.3f})",
            ))

    # Boolean 탐지 — 로그인/ORDER BY 파라미터 제외
    if not _is_login_param(c.target_param) and not _is_orderby_param(c.target_param):
        for and_pair, or_pair in [
            (BOOLEAN_STRING_AND,       BOOLEAN_STRING_OR),
            (BOOLEAN_NUMERIC_AND,      BOOLEAN_NUMERIC_OR),
            (BOOLEAN_STRING_AND_HASH,  BOOLEAN_STRING_OR_HASH),
            (BOOLEAN_NUMERIC_AND_HASH, BOOLEAN_NUMERIC_OR_HASH),
        ]:
            and_true_payload  = render(and_pair["true_payload"],  c.base_value)
            and_false_payload = render(and_pair["false_payload"], c.base_value)
            or_true_payload   = render(or_pair["true_payload"],   c.base_value)
            or_false_payload  = render(or_pair["false_payload"],  c.base_value)
            and_true_body,  _ = _send(c.method, c.base_url, p(and_true_payload),  session)
            and_false_body, _ = _send(c.method, c.base_url, p(and_false_payload), session)
            or_true_body,   _ = _send(c.method, c.base_url, p(or_true_payload),   session)
            or_false_body,  _ = _send(c.method, c.base_url, p(or_false_payload),  session)
            verdict = judge_boolean_sqli(
                baseline_body, and_true_body, and_false_body, or_true_body, or_false_body,
                c.base_value, and_true_payload, and_false_payload, or_true_payload, or_false_payload,
                base_ratio=base_ratio,
            )
            if verdict.vulnerable:
                if "AND 패턴" in verdict.evidence:
                    category, payload = and_pair["family"], and_true_payload
                elif "OR 패턴" in verdict.evidence:
                    category, payload = or_pair["family"], or_true_payload
                else:
                    category, payload = "boolean_unknown", and_true_payload
                findings.append(_to_finding(c, request_id, "sqli", category, payload, verdict.confidence, verdict.evidence))
                break

    for ep in ERROR_BASED_PAYLOADS:
        payload = render(ep, c.base_value)
        attack_body, _ = _send(c.method, c.base_url, p(payload), session)
        verdict = judge_error_based_sqli(baseline_body, attack_body)
        if verdict.vulnerable:
            findings.append(_to_finding(c, request_id, "sqli", "error_based", payload, verdict.confidence, verdict.evidence))
            break

    # UNION-based: 컬럼 수 불일치 에러 탐지
    for up in UNION_PAYLOADS:
        payload = render(up, c.base_value)
        attack_body, _ = _send(c.method, c.base_url, p(payload), session)
        verdict = judge_union_sqli(baseline_body, attack_body)
        if verdict.vulnerable:
            findings.append(_to_finding(c, request_id, "sqli", "union", payload, verdict.confidence, verdict.evidence))
            break

    # Expression-based: 숫자 파라미터에서 수식 평가 여부 탐지
    if _is_numeric(c.base_value):
        n = int(c.base_value)
        equiv_payload    = f"{n + 1}-1"
        nonequiv_payload = f"{n + 2}-1"
        equiv_body,    _ = _send(c.method, c.base_url, p(equiv_payload),    session)
        nonequiv_body, _ = _send(c.method, c.base_url, p(nonequiv_payload), session)
        verdict = judge_expression_sqli(
            baseline_body, equiv_body, nonequiv_body,
            equiv_payload, nonequiv_payload, c.base_value,
            base_ratio=base_ratio,
        )
        if verdict.vulnerable:
            findings.append(_to_finding(c, request_id, "sqli", "expression", equiv_payload, verdict.confidence, verdict.evidence))

    time_payload = TIME_BASED_PAYLOADS[0]
    rendered = render(time_payload, c.base_value)
    elapsed_list = []
    for _ in range(TIME_BASED_REPEAT):
        _, e = _send(c.method, c.base_url, p(rendered), session)
        elapsed_list.append(e)
    verdict = judge_time_based_sqli(baseline_elapsed, elapsed_list)
    if verdict.vulnerable:
        findings.append(_to_finding(c, request_id, "sqli", "time_based", rendered, verdict.confidence, verdict.evidence))

    return findings


def _scan_xss(c: Candidate, request_id: str, scan_cookies: dict) -> list[dict]:
    findings: list[dict] = []
    session = requests.Session()
    session.cookies.update(scan_cookies)

    if c.method == "POST":
        # Stored XSS: baseline GET 먼저 — 이미 저장된 payload와 구분
        baseline_get, _ = _send("GET", c.base_url, {}, session)
        for payload in XSS_PAYLOADS:
            fresh_other = _refresh_csrf_tokens(session, c)
            _send("POST", c.base_url, {**fresh_other, c.target_param: payload}, session)
            after_get, _ = _send("GET", c.base_url, {}, session)
            verdict = judge_xss(after_get, payload)
            if verdict.vulnerable and not judge_xss(baseline_get, payload).vulnerable:
                findings.append(_to_finding(c, request_id, "xss", "stored", payload, verdict.confidence, verdict.evidence))
                break
    else:
        def p(value: str) -> dict:
            return {**c.other_params, c.target_param: value}

        for payload in XSS_PAYLOADS:
            attack_body, _ = _send(c.method, c.base_url, p(payload), session)
            verdict = judge_xss(attack_body, payload)
            if verdict.vulnerable:
                findings.append(_to_finding(c, request_id, "xss", "reflected", payload, verdict.confidence, verdict.evidence))
                break

    return findings


def scan_candidate(c: Candidate, request_id: str, scan_cookies: dict) -> list[dict]:
    findings: list[dict] = []
    findings.extend(_scan_sqli(c, request_id, scan_cookies))
    findings.extend(_scan_xss(c, request_id, scan_cookies))
    return findings

# DEMO_DVWA_AUTH=1 전용. 크롤 후 켜진 PHPIDS를 스캔 전에 끔.
def _demo_dvwa_setup(scan_cookies: dict) -> None:
    base = os.getenv("TARGET_URL", "http://localhost:8080").rstrip("/")
    try:
        s = requests.Session()
        s.cookies.update(scan_cookies)
        s.get(f"{base}/security.php?phpids=off", timeout=TIMEOUT)
        print("[demo] PHPIDS 비활성화")
    except Exception:
        pass


def main() -> None:
    if len(sys.argv) > 1:
        targets_path = sys.argv[1]
        print(f"[analyzer] 기존 run 재사용: {targets_path}")
        with open(targets_path, encoding="utf-8") as f:
            scan_targets = json.load(f)
        session_dir = os.path.dirname(os.path.abspath(targets_path))
    else:
        demo_cookies = get_demo_dvwa_cookies() or None
        session_info = run_crawl_session(override_auth_cookies=demo_cookies)
        session_dir = session_info["session_dir"]
        scan_targets = merge(Path(session_dir))
        save_json(os.path.join(session_dir, "scan_targets.json"), scan_targets)
        print(f"[analyzer] 크롤 + 병합 완료: {session_dir}")

    candidates = load_candidates(scan_targets)
    print(f"[analyzer] {len(candidates)}개 후보 파라미터")

    scan_cookies = get_demo_dvwa_cookies()
    if scan_cookies:
        _demo_dvwa_setup(scan_cookies)

    all_findings: list[dict] = []
    for i, c in enumerate(candidates, 1):
        request_id = f"req-{i:03d}"
        print(f"[{i}/{len(candidates)}] {c.method} {c.base_url} param={c.target_param}")
        try:
            findings = scan_candidate(c, request_id, scan_cookies)
        except Exception as exc:
            print(f"  [ERROR] {exc}")
            continue
        for f in findings:
            print(f"  -> {f['vuln_type']}/{f['category']} confidence={f['confidence']} {f['evidence']}")
        all_findings.extend(findings)

    out_path = os.path.join(session_dir, "findings.json")
    save_json(out_path, all_findings)
    print(f"[analyzer] {len(all_findings)}개 발견, 저장: {out_path}")


if __name__ == "__main__":
    main()

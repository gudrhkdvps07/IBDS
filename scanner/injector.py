"""
scan_targets.json → HTTP task 목록 변환

inject_mode 계약 (executor.py와 인터페이스)
  replace : 파라미터 값을 payload로 완전 교체
  append  : 파라미터 값 = base_value + payload

inject_mode 결정 규칙
  XSS 전체           → replace  (완성된 HTML/JS 페이로드)
  SQLI_ERROR_META    → replace  (메타문자 단독 주입)
  SQLI_BOOLEAN 등    → append   (원본값 + SQL suffix, ZAP origParamValue 방식)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

from scanner.payload import xss as xss_mod
from scanner.payload import sqli as sqli_mod

# CSRF 토큰 갱신이 필요한 파라미터 이름 키워드
_CSRF_KEYWORDS = {"token", "csrf", "nonce"}

# append 방식으로 주입하는 SQLi 타입 집합
_SQLI_APPEND_TYPES = {
    "SQLI_BOOLEAN",
    "SQLI_UNION",
    "SQLI_ORDERBY",
    "SQLI_TIME_MYSQL",
    "SQLI_TIME_PGSQL",
    "SQLI_TIME_MSSQL",
    "SQLI_TIME_ORACLE",
    "SQLI_STACKED",
}


def load_targets(session_dir: str | Path) -> List[dict]:
    """session_dir/scan_targets.json 로드 후 반환"""
    path = Path(session_dir) / "scan_targets.json"
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _base_params(parameters: List[dict]) -> dict:
    """전체 파라미터의 원본값 dict 반환 (scan 여부 무관)
    scan=false인 CSRF 토큰 등도 요청에 포함해야 서버가 정상 처리함"""
    result: dict = {}
    for p in parameters:
        name = p.get("name", "")
        if not name:
            continue
        vals = p.get("sample_values") or []
        result[name] = str(vals[0]) if vals else ""
    return result


def _base_value(param: dict) -> str:
    """파라미터의 첫 번째 샘플값 반환 (없으면 빈 문자열)"""
    vals = param.get("sample_values") or []
    return str(vals[0]) if vals else ""


def _inject_mode(payload_type: str, vuln: str) -> str:
    """payload type → inject_mode 결정"""
    if vuln == "xss":
        return "replace"
    if payload_type == "SQLI_ERROR_META":
        return "replace"
    if payload_type in _SQLI_APPEND_TYPES:
        return "append"
    return "replace"


def _build_tasks_for_target(
    target: dict,
    target_idx: int,
    strength: str,
    scan_xss: bool,
    scan_sqli: bool,
) -> List[dict]:
    """타겟 하나에 대한 task 목록 생성"""
    tasks: List[dict] = []

    url = target.get("base_url", "")
    method = target.get("method", "GET").upper()
    enctype = target.get("enctype", "application/x-www-form-urlencoded")
    cookies = dict(target.get("cookies") or {})
    headers = dict(target.get("headers") or {})
    parameters = target.get("parameters") or []
    role = target.get("role", "guest")

    base_params = _base_params(parameters)

    # scan=true인 파라미터만 주입 대상으로 선택
    scan_params = [p for p in parameters if p.get("scan", True)]

    for param_idx, param in enumerate(scan_params):
        param_name = param.get("name", "")
        location = param.get("request_location", "query")
        orig_value = _base_value(param)

        payloads: List[dict] = []

        if scan_xss:
            for p in xss_mod.get_by_context("unknown", strength):
                payloads.append(("xss", p))

        if scan_sqli:
            for p in sqli_mod.get_by_strength(strength):
                payloads.append(("sqli", p))

        for payload_idx, (vuln, payload_dict) in enumerate(payloads):
            ptype = payload_dict["type"]
            family = payload_dict["family"]
            raw_payload = payload_dict["payload"]
            mode = _inject_mode(ptype, vuln)

            task_id = f"{target_idx}_{param_name}_{vuln}_{payload_idx}"

            tasks.append({
                "id": task_id,
                "url": url,
                "method": method,
                "enctype": enctype,
                "point": param_name,
                "payload": raw_payload,
                "payload_type": ptype,
                "payload_family": family,
                "inject_mode": mode,
                "inject_location": location,
                "inject_param": param_name,
                "base_params": dict(base_params),
                "base_headers": headers,
                "base_cookies": cookies,
                "base_value": orig_value,
                "needs_csrf_refresh": any(
                    not p.get("scan", True)
                    and any(kw in (p.get("name") or "").lower() for kw in _CSRF_KEYWORDS)
                    for p in parameters
                ),
                "source_url": url,
                "meta": {
                    "role": role,
                    "target_index": target_idx,
                    "param_index": param_idx,
                    "vuln_scan": vuln,
                },
            })

    return tasks


def build_tasks(
    targets: List[dict],
    strength: str = "MEDIUM",
    scan_xss: bool = True,
    scan_sqli: bool = True,
) -> List[dict]:
    """scan_targets 목록 → task 목록 변환

    can_scan=false 타겟은 자동으로 제외한다.
    strength: LOW | MEDIUM | HIGH | INSANE
    """
    all_tasks: List[dict] = []

    for idx, target in enumerate(targets):
        if not target.get("can_scan", True):
            continue
        tasks = _build_tasks_for_target(
            target, idx, strength, scan_xss, scan_sqli
        )
        all_tasks.extend(tasks)

    return all_tasks


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("usage: python -m scanner.injector <session_dir> [strength]")
        sys.exit(1)

    session_dir = sys.argv[1]
    strength = sys.argv[2] if len(sys.argv) > 2 else "MEDIUM"

    targets = load_targets(session_dir)
    tasks = build_tasks(targets, strength=strength)

    scannable = sum(1 for t in targets if t.get("can_scan", True))
    print(f"targets={len(targets)}  can_scan={scannable}")
    print(f"tasks={len(tasks)}  strength={strength}")

    by_vuln: dict = {}
    for t in tasks:
        v = t["meta"]["vuln_scan"]
        by_vuln[v] = by_vuln.get(v, 0) + 1
    for v, cnt in sorted(by_vuln.items()):
        print(f"  {v}: {cnt}개")

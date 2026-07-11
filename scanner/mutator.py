"""
XSS / SQLi finding → WAF 우회 변형 task 목록

진입점: build_mutated_tasks(findings, original_tasks) → List[dict]
"""

from __future__ import annotations

import re
from typing import List


# ── XSS mutations ──────────────────────────────────────────────────────────────
#
# ZAP CrossSiteScriptingScanRule.mutateAttack() 기반.
#
# Group 1: ( → `  ) → `   (괄호 차단 WAF 우회)
# Group 2: < → ＜  > → ＞  (각도 괄호 차단 WAF 우회, 전각문자)
# Group 3: 1+2 동시 적용

_MUTATIONS: List[List[tuple[str, str]]] = [
    [("(", "`"), (")", "`")],
    [("<", "＜"), (">", "＞")],
    [("(", "`"), (")", "`"), ("<", "＜"), (">", "＞")],
]

_APPLICABLE_CONFIDENCE = {"confirmed", "suspected"}


def mutate_payload(payload: str) -> List[dict]:
    """XSS 페이로드 mutation 목록 반환."""
    results: List[dict] = []
    for group_idx, group in enumerate(_MUTATIONS):
        original_chars = [pair[0] for pair in group]
        if not any(c in payload for c in original_chars):
            continue
        mutated = payload
        for orig, replacement in group:
            mutated = mutated.replace(orig, replacement)
        if mutated == payload:
            continue
        desc = ", ".join(f"{o}→{r}" for o, r in group)
        results.append({
            "payload":     mutated,
            "group":       group_idx + 1,
            "description": f"group{group_idx + 1}: {desc}",
        })
    return results


# ── SQLi mutations ─────────────────────────────────────────────────────────────
#
# ZAP SqlInjectionScanRule에는 XSS처럼 별도 mutateAttack() 가 없으므로
# SQLMap tamper script + OWASP Testing Guide 기법을 적용.
#
# S1: 공백 → /**/       (space2comment — MySQL/PgSQL/MSSQL 모두 인식)
# S2: " -- " → " #"    (MySQL hash comment 우회)
# S3: 예약어 대소문자 혼용  (AnD, oR, SeLeCt — regex 시그니처 우회)
# S4: S1 + S3 동시 적용
#
# 제외: SLEEP / pg_sleep / dbms_pipe 등 함수명은 대소문자 혼용 시 DB 미인식 위험

_SQLI_KEYWORD_RE = re.compile(
    r"\b(AND|OR|NOT|SELECT|UNION|ALL|WHERE|ORDER|BY|FROM|HAVING|GROUP|"
    r"LIMIT|OFFSET|IN|EXISTS|BETWEEN|LIKE|WAITFOR|DELAY|NULL)\b",
    re.IGNORECASE,
)


def _mix_case(word: str) -> str:
    """짝수 인덱스 대문자, 홀수 인덱스 소문자."""
    return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(word))


def mutate_sqli_payload(payload: str) -> List[dict]:
    """SQLi 페이로드 mutation 목록 반환.

    ERROR_META(단일 메타문자) 등 공백/키워드 없는 payload는 빈 목록.
    """
    results: List[dict] = []

    # S1: 공백 → /**/
    s1 = payload.replace(" ", "/**/") if " " in payload else None
    if s1 and s1 != payload:
        results.append({"payload": s1, "group": "S1", "description": "space→/**/"})

    # S2: " -- " → " #"  (MySQL hash comment)
    if " -- " in payload:
        s2 = payload.replace(" -- ", " #")
        if s2 != payload:
            results.append({"payload": s2, "group": "S2", "description": "comment -- →#"})

    # S3: 예약어 대소문자 혼용
    s3 = _SQLI_KEYWORD_RE.sub(lambda m: _mix_case(m.group()), payload)
    if s3 != payload:
        results.append({"payload": s3, "group": "S3", "description": "keyword case mix"})
    else:
        s3 = None

    # S4: S1 + S3 동시
    if s1 and s3:
        s4_base = _SQLI_KEYWORD_RE.sub(lambda m: _mix_case(m.group()), payload)
        s4 = s4_base.replace(" ", "/**/")
        if s4 not in {payload, s1, s3}:
            results.append({"payload": s4, "group": "S4", "description": "space→/**/ + case mix"})

    return results


# ── 공통 진입점 ────────────────────────────────────────────────────────────────

def build_mutated_tasks(
    findings: List[dict],
    original_tasks: List[dict],
) -> List[dict]:
    """XSS / SQLi finding → mutation 변형 task 목록.

    - confidence가 confirmed / suspected 인 finding만 대상
    - original_tasks에서 (url, inject_param, payload) 로 원본 task를 찾아
      HTTP 컨텍스트를 복사하고 payload만 변형 버전으로 교체
    """
    if not findings or not original_tasks:
        return []

    # (url, inject_param, payload) → task 빠른 조회
    task_index: dict[tuple, dict] = {}
    for t in original_tasks:
        key = (t.get("url"), t.get("inject_param"), t.get("payload"))
        task_index[key] = t

    out: List[dict] = []

    xss_findings = [
        f for f in findings
        if f.get("vuln_type") == "XSS"
        and f.get("confidence") in _APPLICABLE_CONFIDENCE
    ]
    for finding in xss_findings:
        orig_key = (finding.get("url"), finding.get("param"), finding.get("payload"))
        orig_task = task_index.get(orig_key)
        if not orig_task:
            continue
        for m in mutate_payload(finding.get("payload") or ""):
            task = dict(orig_task)
            task["id"] = f"mut_{orig_task.get('id', 'x')}_xss_g{m['group']}"
            task["payload"] = m["payload"]
            task["payload_family"] = f"mutated_xss_g{m['group']}"
            task["meta"] = {
                **(orig_task.get("meta") or {}),
                "mutation_group":      m["group"],
                "mutation_desc":       m["description"],
                "original_payload":    finding.get("payload"),
                "original_confidence": finding.get("confidence"),
            }
            out.append(task)

    sqli_findings = [
        f for f in findings
        if f.get("vuln_type") == "SQLI"
        and f.get("confidence") in _APPLICABLE_CONFIDENCE
    ]
    for finding in sqli_findings:
        orig_key = (finding.get("url"), finding.get("param"), finding.get("payload"))
        orig_task = task_index.get(orig_key)
        if not orig_task:
            continue
        for m in mutate_sqli_payload(finding.get("payload") or ""):
            task = dict(orig_task)
            task["id"] = f"mut_{orig_task.get('id', 'x')}_sqli_{m['group']}"
            task["payload"] = m["payload"]
            task["payload_family"] = f"mutated_sqli_{m['group']}"
            task["meta"] = {
                **(orig_task.get("meta") or {}),
                "mutation_group":      m["group"],
                "mutation_desc":       m["description"],
                "original_payload":    finding.get("payload"),
                "original_confidence": finding.get("confidence"),
            }
            out.append(task)

    return out

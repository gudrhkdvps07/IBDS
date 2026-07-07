"""
XSS finding → WAF 우회 변형 task 목록

ZAP CrossSiteScriptingScanRule.mutateAttack() 기반.
MUTATIONS 2그룹을 독립적으로 적용하며, 각 그룹은 서로 조합하지 않는다.

Group 1: ( → `  ) → `   (WAF가 괄호를 차단하는 경우)
Group 2: < → ＜  > → ＞  (WAF가 각도 괄호를 차단하는 경우, 전각문자 대체)

checkOriginal(Group 2): ZAP은 mutatedEvidence는 원본 <> 기준으로 탐지하고
attack에만 전각문자를 적용한다. IBDS에서는 analyzer가 재분석하므로 별도 처리 불필요.

진입점: build_mutated_tasks(findings, original_tasks) → List[dict]
"""

from __future__ import annotations

from typing import List

# (original_char, replacement_char) 쌍의 그룹 목록
# ZAP MUTATIONS 3그룹과 동일
_MUTATIONS: List[List[tuple[str, str]]] = [
    [("(", "`"), (")", "`")],                                       # Group 1: 괄호 → 백틱
    [("<", "＜"), (">", "＞")],                                     # Group 2: 각도 괄호 → 전각문자
    [("(", "`"), (")", "`"), ("<", "＜"), (">", "＞")],            # Group 3: 1+2 동시 적용
]

# mutation을 적용할 finding confidence 범위
_APPLICABLE_CONFIDENCE = {"confirmed", "suspected"}


def mutate_payload(payload: str) -> List[dict]:
    """페이로드에 적용 가능한 mutation 변형 목록 반환.

    각 그룹에서 첫 번째 원본 문자가 payload에 없으면 해당 그룹은 건너뜀.
    변형이 없으면 빈 목록.
    """
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


def build_mutated_tasks(
    findings: List[dict],
    original_tasks: List[dict],
) -> List[dict]:
    """XSS finding → mutation 변형 task 목록.

    - XSS vuln_type, confirmed/suspected confidence인 finding만 대상
    - original_tasks에서 (url, inject_param, payload) 조합으로 원본 task를 찾아
      HTTP 컨텍스트(base_params, cookies, headers 등)를 그대로 복사
    - payload만 변형된 버전으로 교체
    """
    xss_findings = [
        f for f in findings
        if f.get("vuln_type") == "XSS"
        and f.get("confidence") in _APPLICABLE_CONFIDENCE
    ]
    if not xss_findings or not original_tasks:
        return []

    # (url, inject_param, payload) → task 빠른 조회
    task_index: dict[tuple, dict] = {}
    for t in original_tasks:
        key = (t.get("url"), t.get("inject_param"), t.get("payload"))
        task_index[key] = t

    out: List[dict] = []

    for finding in xss_findings:
        orig_key = (finding.get("url"), finding.get("param"), finding.get("payload"))
        orig_task = task_index.get(orig_key)
        if not orig_task:
            continue

        mutations = mutate_payload(finding.get("payload") or "")
        for m in mutations:
            task = dict(orig_task)
            task["id"] = f"mut_{orig_task.get('id', 'x')}_g{m['group']}"
            task["payload"] = m["payload"]
            task["payload_family"] = f"mutated_g{m['group']}"
            task["meta"] = {
                **(orig_task.get("meta") or {}),
                "mutation_group":       m["group"],
                "mutation_desc":        m["description"],
                "original_payload":     finding.get("payload"),
                "original_confidence":  finding.get("confidence"),
            }
            out.append(task)

    return out

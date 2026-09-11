"""
request_results.jsonl -> XSS 판정(raw) + headless confirm -> xss_findings.jsonl
analyzer/xss/judge.py는 수정하지 안하고 사용. sqli는 아직 제대로 merge 할 수 있는 상태가 아니라서 건너뜀.
"""
from __future__ import annotations

import difflib
import json
import os
from dataclasses import asdict, dataclass

from scan.models import RequestFamily, CaseResult
from utilities.file_utils import append_jsonl
from .headless import HeadlessSession
from .xss.judge import judge_xss

_DOM_TECHNIQUE = "dom"
_STORED_TECHNIQUE = "stored"


@dataclass
class Finding:  # xss_findings.jsonl 한 줄에 대응하는 case 단위 판정 결과
    family_id: str
    target_id: str
    param: str
    attack_id: str
    technique: str
    case_id: str
    payload: str | None
    raw_verdict: dict              # judge_xss 결과 (asdict)
    headless_checked: bool         # headless 대상이었는지
    headless_verdict: dict | None  # headless 결과 (asdict), 대상 아니면 None
    final_status: str              # "vulnerable" | "reflected_only" | "safe" | "inconclusive"


# raw 판정에서 걸렸거나, raw로는 원천적으로 확인이 안 되는 기법(dom)이면 headless 대상
def _is_headless_target(vulnerable: bool, technique: str) -> bool:
    return vulnerable or technique == _DOM_TECHNIQUE


# headless 확인 결과까지 반영한 최종 상태 판정
def _final_status(raw_vulnerable: bool, headless_checked: bool, executed: bool) -> str:
    if not headless_checked:
        return "safe"
    if executed:
        return "vulnerable"
    return "reflected_only" if raw_vulnerable else "safe"


# Finding 생성 헬퍼 (stored 분기용) — raw/headless 없으면 기본값 채움
def _mk_finding(family: dict, case: dict, final_status: str, *, raw=None, hv=None, evidence: str = "") -> Finding:
    return Finding(
        family_id=family["family_id"],
        target_id=family["target_id"],
        param=family["param"],
        attack_id=family["attack_id"],
        technique=family["technique"],
        case_id=case["case_id"],
        payload=case.get("payload"),
        raw_verdict=asdict(raw) if raw else {"vulnerable": False, "confidence": "", "evidence": evidence},
        headless_checked=hv is not None,
        headless_verdict=asdict(hv) if hv else None,
        final_status=final_status,
    )



def _diff_new_region(before: str, after: str) -> str | None:
    added = [ln[2:] for ln in difflib.ndiff(before.splitlines(), after.splitlines())
             if ln.startswith("+ ")]
    return "\n".join(added) if added else None


# stored 판정: 재조회 전/후 diff → 새 영역만 judge_xss → 실제 발화(navigate) 확인
def _judge_stored(family: dict, case_result: dict, headless: HeadlessSession) -> Finding:
    case = case_result["case"]
    payload = case.get("payload") or ""

    if not family.get("sink_confirmed"):  # sink 미확인 family는 판정 불가 (safe로 안 뭉갬)
        return _mk_finding(family, case, "inconclusive", evidence="sink 미확인")

    before = case_result.get("before_revisit_body") or ""
    after = case_result.get("revisit_body") or ""
    post_body = case_result.get("response_body") or ""  # 공격 POST 응답 (에코 판별용)

    # found(payload가 재조회에 떴는지)로 판단 (attempts 숫자 비교 X, off-by-one 방지)
    found = bool(payload) and payload in after
    if not found:  #재조회엔 없음
        if payload and payload in post_body:  # POST엔 에코됨 → 반사만, 저장 아님
            return _mk_finding(family, case, "reflected_only", evidence="POST 에코, 재조회 미저장")
        return _mk_finding(family, case, "inconclusive", evidence="재조회에 payload 미확인")

    new_region = _diff_new_region(before, after)  # diff 게이트: 이번에 새로 생긴 영역
    if not new_region:  
        return _mk_finding(family, case, "safe", evidence="재조회에 새 영역 없음(기존 잔재)")

    raw = judge_xss(new_region, payload) 
    if not raw.vulnerable:
        return _mk_finding(family, case, "safe", raw=raw, evidence="새 영역에 실행가능 반사 없음")

    hv = headless.confirm_via_navigate(  # 실제 발화 확인 — revisit 페이지를 headless로 열어봄
        case_result.get("revisit_url_used") or case["url"],
        case_result.get("effective_cookies") or {},
        "GET",
    )
    return _mk_finding(family, case, "vulnerable" if hv.executed else "reflected_only", raw=raw, hv=hv)


# mutation case 1건에 대한 raw 판정 + (필요시) headless 확인
def judge_case(family: dict, case_result: dict, headless: HeadlessSession) -> Finding:
    case = case_result["case"]
    technique = family["technique"]
    payload = case.get("payload") or ""

    if case_result.get("status") == "error":  # 요청 자체가 실패한 case는 judge_xss/headless 호출 없이 즉시 safe 처리
        return Finding(
            family_id=family["family_id"],
            target_id=family["target_id"],
            param=family["param"],
            attack_id=family["attack_id"],
            technique=technique,
            case_id=case["case_id"],
            payload=case.get("payload"),
            raw_verdict={"vulnerable": False, "confidence": "", "evidence": "요청 실패로 판정 불가"},
            headless_checked=False,
            headless_verdict=None,
            final_status="safe",
        )

    if technique == _STORED_TECHNIQUE:  # stored는 재조회 diff 게이트 경로로 분기
        return _judge_stored(family, case_result, headless)

    raw_verdict = judge_xss(case_result.get("response_body") or "", payload)
    headless_checked = _is_headless_target(raw_verdict.vulnerable, technique)

    headless_verdict = None
    if headless_checked:
        if technique == _DOM_TECHNIQUE:
            headless_verdict = headless.confirm_via_navigate(
                case["url"], case_result.get("effective_cookies") or {}, case["method"],
            )
        else:
            headless_verdict = headless.confirm_via_render(case_result.get("response_body") or "")

    return Finding(
        family_id=family["family_id"],
        target_id=family["target_id"],
        param=family["param"],
        attack_id=family["attack_id"],
        technique=technique,
        case_id=case["case_id"],
        payload=case.get("payload"),
        raw_verdict=asdict(raw_verdict),
        headless_checked=headless_checked,
        headless_verdict=asdict(headless_verdict) if headless_verdict else None,
        final_status=_final_status(
            raw_verdict.vulnerable, headless_checked,
            headless_verdict.executed if headless_verdict else False,
        ),
    )


# request_results.jsonl을 읽어 XSS family만 판정, xss_findings.jsonl 생성
def run(results_path: str, headless: HeadlessSession | None = None) -> str:
    out_path = os.path.join(os.path.dirname(results_path), "xss_findings.jsonl")
    if os.path.exists(out_path):
        os.remove(out_path)  # append_jsonl은 이어쓰기라 재실행 시 중복 방지

    owns_headless = headless is None
    headless = headless or HeadlessSession()
    non_xss_skipped = 0

    try:
        with open(results_path, encoding="utf-8") as f:
            for line in f:
                family = json.loads(line)
                if family["vuln_type"] != "xss":
                    non_xss_skipped += 1
                    continue
                for case_result in family["mutations"]:
                    try:  # 개별 case 판정 실패는 로그만 남기고 계속 진행
                        finding = judge_case(family, case_result, headless)
                    except Exception as e:
                        print(f"[ERROR] XSS 판정 실패: family={family['family_id']} case={case_result.get('case', {}).get('case_id')} - {e}")
                        continue
                    append_jsonl(out_path, asdict(finding))
    finally:
        if owns_headless:
            headless.close()

    print(f"[JUDGE] xss_findings.jsonl -> {out_path} ({non_xss_skipped}건 non-XSS family는 판정 로직 미연결 - 건너뜀)")
    return out_path

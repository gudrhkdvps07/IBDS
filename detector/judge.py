from __future__ import annotations

import html
from dataclasses import dataclass
from urllib.parse import quote

from .payloads import DB_ERROR_KEYWORDS

# Time-based 기준
SLEEP_THRESHOLD = 4.5    # SLEEP(5) 페이로드 기준, 이 이상 걸리면 "느림"
MIN_REPEAT_CONFIRM = 2   # 최소 이 횟수만큼 재현돼야 confirmed


@dataclass
class SqliVerdict:
    vulnerable: bool
    confidence: str
    evidence: str


# ZAP SqlInjectionScanRule.stripOff() 방식: 원문 + 인코딩된 변형들을 다 지운다
def _strip_value(body: str, value: str) -> str:
    if not value:
        return body
    variants = {value, quote(value), html.escape(value), html.escape(quote(value))}
    for v in variants:
        if v:
            body = body.replace(v, "")
    return body


# ZAP testBooleanBasedSqlInjection() 순서를 그대로 따른다:
# AND-true가 baseline과 같아야만(게이트) AND-false를 보고, AND-false도 baseline과
# 같으면(원래 결과가 비어있었을 수 있음) 그제서야 OR-true를 본다.
# AND-true가 baseline과 다르면 즉시 안전 처리 — base_value가 빈 문자열일 때
# "값이 비어있다가 채워지는 것" 자체로 페이지 구조가 바뀌는 경우의 오탐을 막기 위함
# (xss_r 실측에서 발견된 문제).
def judge_boolean_sqli(
    baseline_body: str,
    and_true_body: str, and_false_body: str, or_true_body: str,
    base_value: str,
    and_true_payload: str, and_false_payload: str, or_true_payload: str,
) -> SqliVerdict:
    base_clean      = _strip_value(baseline_body, base_value)
    and_true_clean  = _strip_value(and_true_body, and_true_payload)
    and_false_clean = _strip_value(and_false_body, and_false_payload)
    or_true_clean   = _strip_value(or_true_body, or_true_payload)

    # 게이트: AND-true가 baseline과 다르면 SQL 논리로 해석 안 되는 것 -> 포기
    if and_true_clean != base_clean:
        return SqliVerdict(False, "", "AND-true가 baseline과 다름 — SQL 논리로 해석되지 않음 (안전)")

    # AND-false가 다르면 -> AND 패턴 확정
    if and_false_clean != base_clean:
        return SqliVerdict(
            True, "high",
            "Boolean SQLi (AND 패턴): AND-true==baseline, AND-false는 다름"
        )

    # AND-false도 같다 -> 원래 결과가 비어있었을 수 있음, OR-true로 한 번 더 확인
    if or_true_clean != base_clean:
        return SqliVerdict(
            True, "high",
            "Boolean SQLi (OR 패턴): AND만으론 차이 없었으나 OR-true에서 확장 확인됨"
        )

    return SqliVerdict(False, "", "AND/OR 모두 baseline과 동일 — 안전")


def judge_error_based_sqli(baseline_body: str, attack_body: str) -> SqliVerdict:
    base_lower = (baseline_body or "").lower()
    attack_lower = (attack_body or "").lower()

    for kw in DB_ERROR_KEYWORDS:
        if kw in attack_lower and kw not in base_lower:
            return SqliVerdict(True, "high", f"Error-based SQLi: baseline에는 없던 DB 에러 노출 ('{kw}')")

    for kw in DB_ERROR_KEYWORDS:
        if kw in attack_lower and kw in base_lower:
            return SqliVerdict(False, "", f"DB 에러 문구가 baseline에도 있음 — 이 페이지의 정상 동작 ('{kw}')")

    return SqliVerdict(False, "", "DB 에러 시그니처 없음")



def judge_time_based_sqli(baseline_elapsed: float, attack_elapsed_list: list[float]) -> SqliVerdict:
    """attack_elapsed_list: 같은 time-based 페이로드를 여러 번 보낸 각각의 elapsed time."""
    slow_count = sum(1 for e in attack_elapsed_list if e >= SLEEP_THRESHOLD)

    if slow_count == 0:
        return SqliVerdict(False, "", f"지연 응답 없음 (모두 {SLEEP_THRESHOLD}s 미만, baseline={baseline_elapsed:.2f}s)")

    if slow_count >= MIN_REPEAT_CONFIRM:
        avg = sum(attack_elapsed_list) / len(attack_elapsed_list)
        return SqliVerdict(
            True, "high",
            f"Time-based SQLi (confirmed): {slow_count}/{len(attack_elapsed_list)}회 지연 재현 "
            f"(평균 {avg:.2f}s, baseline {baseline_elapsed:.2f}s)"
        )

    return SqliVerdict(
        True, "medium",
        f"Time-based SQLi (suspected): {slow_count}/{len(attack_elapsed_list)}회만 지연 — "
        f"재현성 부족, 추가 검증 필요"
    )

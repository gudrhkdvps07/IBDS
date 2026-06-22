from __future__ import annotations

import html
from dataclasses import dataclass
from difflib import SequenceMatcher
from urllib.parse import quote

from .payloads import DB_ERROR_KEYWORDS

# Time-based 기준
SLEEP_THRESHOLD = 4.5
MIN_REPEAT_CONFIRM = 2

# Boolean 비교 기준
_NOISY_DELTA = 0.05


@dataclass
class SqliVerdict:
    vulnerable: bool
    confidence: str
    evidence: str


def _strip_value(body: str, value: str) -> str:
    if not value:
        return body
    variants = {value, quote(value), html.escape(value), html.escape(quote(value))}
    for v in variants:
        if v:
            body = body.replace(v, "")
    return body


def _noise_floor(base_ratio: float) -> float:
    if base_ratio == 1.0:
        return 1.0                   # exact 비교
    return base_ratio - _NOISY_DELTA # 동적 페이지


def _is_same(a: str, b: str, floor: float) -> bool:
    return SequenceMatcher(None, a, b).ratio() >= floor


def _is_different(a: str, b: str, floor: float) -> bool:
    return not _is_same(a, b, floor)


def judge_boolean_sqli(
    baseline_body: str,
    and_true_body: str, and_false_body: str, or_true_body: str,
    base_value: str,
    and_true_payload: str, and_false_payload: str, or_true_payload: str,
    base_ratio: float = 1.0,
) -> SqliVerdict:
    floor = _noise_floor(base_ratio)

    base_clean      = _strip_value(baseline_body, base_value)
    and_true_clean  = _strip_value(and_true_body, and_true_payload)
    and_false_clean = _strip_value(and_false_body, and_false_payload)
    or_true_clean   = _strip_value(or_true_body, or_true_payload)

    # AND-true 게이트: baseline과 같아야 통과 (동적 콘텐츠도 허용)
    if _is_different(and_true_clean, base_clean, floor):
        return SqliVerdict(False, "", "AND-true가 baseline과 다름 — SQL 논리로 해석되지 않음 (안전)")

    # 탐지 판정: baseline과 달라야 SQLi
    if _is_different(and_false_clean, base_clean, floor):
        return SqliVerdict(
            True, "high",
            f"Boolean SQLi (AND 패턴): AND-true==baseline, AND-false는 다름 (floor={floor:.3f})"
        )

    if _is_different(or_true_clean, base_clean, floor):
        return SqliVerdict(
            True, "high",
            f"Boolean SQLi (OR 패턴): AND만으론 차이 없었으나 OR-true에서 확장 확인됨 (floor={floor:.3f})"
        )

    return SqliVerdict(False, "", "AND/OR 모두 baseline과 동일 — 안전")


def judge_error_based_sqli(baseline_body: str, attack_body: str) -> SqliVerdict:
    base_lower   = (baseline_body or "").lower()
    attack_lower = (attack_body or "").lower()

    for kw in DB_ERROR_KEYWORDS:
        if kw in attack_lower and kw not in base_lower:
            return SqliVerdict(True, "high", f"Error-based SQLi: baseline에는 없던 DB 에러 노출 ('{kw}')")

    for kw in DB_ERROR_KEYWORDS:
        if kw in attack_lower and kw in base_lower:
            return SqliVerdict(False, "", f"DB 에러 문구가 baseline에도 있음 — 이 페이지의 정상 동작 ('{kw}')")

    return SqliVerdict(False, "", "DB 에러 시그니처 없음")


def judge_time_based_sqli(baseline_elapsed: float, attack_elapsed_list: list[float]) -> SqliVerdict:
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

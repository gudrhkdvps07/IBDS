"""
payload/sqli.py 단위 테스트

실행: pytest tests/test_payload.py -v
"""

import pytest
from scanner.payload.sqli import (
    match_error,
    get_by_strength,
    get_by_category,
    _CATEGORY_MAP,
    BOOLEAN_AND_TRUE,
    BOOLEAN_AND_FALSE,
    BOOLEAN_OR_TRUE,
)
from scanner.payload._utils import _dedupe


# ── match_error ────────────────────────────────────────────────────────────────

class TestMatchError:

    def test_mysql_error(self):
        result = match_error("you have an error in your sql syntax near '1'")
        assert result is not None and result[0] == "MySQL"

    def test_mysql_case_insensitive(self):
        result = match_error("YOU HAVE AN ERROR IN YOUR SQL SYNTAX")
        assert result is not None and result[0] == "MySQL"

    def test_postgresql_error(self):
        result = match_error("unterminated quoted string at or near \"test\"")
        assert result is not None and result[0] == "PostgreSQL"

    def test_oracle_error(self):
        result = match_error("ORA-00933: SQL command not properly ended")
        assert result is not None and result[0] == "Oracle"

    def test_mssql_error(self):
        result = match_error("Unclosed quotation mark after the character string")
        assert result is not None and result[0] == "MSSQL"

    def test_sqlite_error(self):
        result = match_error('near "foo": syntax error')
        assert result is not None and result[0] == "SQLite"

    def test_no_error_returns_none(self):
        assert match_error("welcome to the homepage, enjoy your stay") is None

    def test_empty_string_returns_none(self):
        assert match_error("") is None

    def test_returns_matched_fragment(self):
        result = match_error("you have an error in your sql syntax near ''")
        assert result is not None
        _, fragment = result
        assert len(fragment) > 0


# ── payload pool 중복 & 강도 제한 ─────────────────────────────────────────────

class TestPayloadPool:

    def test_no_duplicate_in_strength_pool(self):
        pool = get_by_strength("INSANE")
        payloads = [p["payload"] for p in pool]
        assert len(payloads) == len(set(payloads)), \
            f"중복 payload 존재: {[p for p in payloads if payloads.count(p) > 1]}"

    def test_limit_low(self):
        assert len(get_by_strength("LOW")) <= 4

    def test_limit_medium(self):
        assert len(get_by_strength("MEDIUM")) <= 10

    def test_limit_high(self):
        assert len(get_by_strength("HIGH")) <= 25

    def test_insane_has_more_than_high(self):
        assert len(get_by_strength("INSANE")) > len(get_by_strength("HIGH"))

    def test_low_is_subset_order_of_medium(self):
        low = get_by_strength("LOW")
        medium = get_by_strength("MEDIUM")
        low_payloads = [p["payload"] for p in low]
        medium_payloads = [p["payload"] for p in medium]
        assert low_payloads == medium_payloads[:len(low)]


# ── _CATEGORY_MAP['boolean'] 중복 제거 ────────────────────────────────────────

class TestCategoryMapBoolean:

    # [회귀 Round6 Fix3] _BOOL_INTERLEAVED 내 OR_TRUE LIKE = AND_TRUE LIKE payload 중복
    def test_boolean_category_no_duplicate_payloads(self):
        pool = _CATEGORY_MAP["boolean"]
        payloads = [p["payload"] for p in pool]
        assert len(payloads) == len(set(payloads)), \
            f"_CATEGORY_MAP['boolean'] 중복 payload: {[p for p in payloads if payloads.count(p) > 1]}"

    def test_boolean_category_contains_and_true(self):
        pool = _CATEGORY_MAP["boolean"]
        families = {p["family"] for p in pool}
        assert "and_int_cmt_true" in families

    def test_boolean_category_contains_and_false(self):
        pool = _CATEGORY_MAP["boolean"]
        families = {p["family"] for p in pool}
        assert "and_int_cmt_false" in families

    def test_boolean_category_contains_or_true(self):
        pool = _CATEGORY_MAP["boolean"]
        families = {p["family"] for p in pool}
        assert "or_int_cmt_true" in families

    def test_bool_and_category_no_or_payloads(self):
        pool = _CATEGORY_MAP["bool_and"]
        families = {p["family"] for p in pool}
        assert not any(f.startswith("or_") for f in families)

    def test_bool_or_category_no_duplicate_with_and_true(self):
        # bool_or에 AND_TRUE와 동일 payload 없어야 함
        and_true_payloads = {p["payload"] for p in BOOLEAN_AND_TRUE}
        bool_or_pool = _CATEGORY_MAP["bool_or"]
        overlap = [p["payload"] for p in bool_or_pool if p["payload"] in and_true_payloads]
        assert len(overlap) == 0, f"bool_or에 AND_TRUE 중복 payload: {overlap}"


# ── AND/FALSE/OR 페이로드 구성 일관성 ─────────────────────────────────────────

class TestPayloadConsistency:

    def test_and_true_false_same_length(self):
        assert len(BOOLEAN_AND_TRUE) == len(BOOLEAN_AND_FALSE), \
            "AND_TRUE / AND_FALSE 개수 불일치"

    def test_and_true_or_true_same_length(self):
        assert len(BOOLEAN_AND_TRUE) == len(BOOLEAN_OR_TRUE), \
            "AND_TRUE / OR_TRUE 개수 불일치"

    def test_and_true_family_suffix(self):
        for p in BOOLEAN_AND_TRUE:
            assert p["family"].endswith("_true"), \
                f"{p['payload_family']} must end with _true"

    def test_and_false_family_suffix(self):
        for p in BOOLEAN_AND_FALSE:
            assert p["family"].endswith("_false"), \
                f"{p['payload_family']} must end with _false"

    def test_or_true_family_prefix_and_suffix(self):
        for p in BOOLEAN_OR_TRUE:
            assert p["family"].startswith("or_"), \
                f"{p['payload_family']} must start with or_"
            assert p["family"].endswith("_true"), \
                f"{p['payload_family']} must end with _true"

    def test_all_boolean_payloads_have_type(self):
        for lst in (BOOLEAN_AND_TRUE, BOOLEAN_AND_FALSE, BOOLEAN_OR_TRUE):
            for p in lst:
                assert p["type"] == "SQLI_BOOLEAN"

    def test_dedupe_removes_or_true_like_duplicates(self):
        # AND_TRUE LIKE과 OR_TRUE LIKE의 payload가 동일 → dedupe 후 제거돼야 함
        and_like_payloads = {p["payload"] for p in BOOLEAN_AND_TRUE
                             if "like" in p["family"]}
        or_like_payloads = {p["payload"] for p in BOOLEAN_OR_TRUE
                            if "like" in p["family"]}
        assert and_like_payloads & or_like_payloads, "테스트 전제: LIKE payload 중복 있어야 함"

        from scanner.payload.sqli import _BOOL_INTERLEAVED
        deduped = _dedupe([_BOOL_INTERLEAVED])
        deduped_payloads = [p["payload"] for p in deduped]
        # dedupe 후에는 중복 없음
        assert len(deduped_payloads) == len(set(deduped_payloads))


# ── _dedupe 유틸 ───────────────────────────────────────────────────────────────

class TestDedupe:

    def test_removes_duplicates(self):
        g1 = [{"payload": "a"}, {"payload": "b"}]
        g2 = [{"payload": "b"}, {"payload": "c"}]
        result = _dedupe([g1, g2])
        payloads = [p["payload"] for p in result]
        assert payloads == ["a", "b", "c"]

    def test_preserves_first_occurrence(self):
        g1 = [{"payload": "x", "type": "FIRST"}]
        g2 = [{"payload": "x", "type": "SECOND"}]
        result = _dedupe([g1, g2])
        assert len(result) == 1 and result[0]["type"] == "FIRST"

    def test_empty_groups(self):
        assert _dedupe([]) == []
        assert _dedupe([[]]) == []

    def test_single_group_no_change(self):
        g = [{"payload": "a"}, {"payload": "b"}, {"payload": "c"}]
        result = _dedupe([g])
        assert [p["payload"] for p in result] == ["a", "b", "c"]

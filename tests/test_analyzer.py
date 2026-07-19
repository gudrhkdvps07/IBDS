"""
analyzer.py 단위 테스트

실행: pytest tests/test_analyzer.py -v

목적:
  코드 리뷰(정적 분석)로 잡은 버그가 실제로 존재했는지, 수정 후 재발하지 않는지 검증.
  각 라운드에서 발견된 회귀 케이스는 [회귀 RoundN] 주석으로 표시.
"""

import pytest
from scanner.analyzer import (
    _bool_classify,
    _compare_bool,
    _detect_boolean,
    _detect_orderby,
    _find_xss,
    _find_sqli_single,
)


# ── 공통 헬퍼 ─────────────────────────────────────────────────────────────────

def make_bool_r(family: str, payload: str = "", body: str = "x" * 200) -> dict:
    return {
        "payload_family": family,
        "payload": payload,
        "response_body": body,
        "payload_type": "SQLI_BOOLEAN",
        "url": "http://target/q",
        "inject_param": "id",
    }


def make_r(**kw) -> dict:
    base = {
        "url": "http://target/q",
        "inject_param": "id",
        "payload": "",
        "payload_type": "",
        "payload_family": "",
        "response_body": "",
        "elapsed": 0.0,
        "status": 200,
        "meta": {"vuln_scan": "sqli"},
        "error": None,
    }
    base.update(kw)
    return base


# ── _bool_classify ─────────────────────────────────────────────────────────────

class TestBoolClassify:

    def test_and_true_family(self):
        assert _bool_classify(make_bool_r("and_int_cmt_true")) == "true"

    def test_and_false_family(self):
        assert _bool_classify(make_bool_r("and_sq_cmt_false")) == "false"

    def test_and_like_true_family(self):
        assert _bool_classify(make_bool_r("and_like_true")) == "true"

    # [회귀 Round3] OR_TRUE가 'true'로 분류되면 avg_pos가 왜곡됨
    def test_or_true_family_must_return_or_true(self):
        assert _bool_classify(make_bool_r("or_int_cmt_true")) == "or_true"

    def test_or_like_sq_cmt_true_family(self):
        assert _bool_classify(make_bool_r("or_like_sq_cmt_true")) == "or_true"

    def test_no_family_true_regex(self):
        assert _bool_classify(make_bool_r("", " AND 1=1 -- ")) == "true"

    def test_no_family_false_regex(self):
        assert _bool_classify(make_bool_r("", " AND 1=2 -- ")) == "false"

    def test_no_family_or_regex_returns_true_not_or_true(self):
        # family 없이 regex만 매치될 때 OR 1=1 → _BOOL_TRUE_RE 매치 → 'true'
        # (or_true는 family suffix로만 구분)
        result = _bool_classify(make_bool_r("", " OR 1=1 -- "))
        assert result == "true"

    def test_unknown_when_no_match(self):
        assert _bool_classify(make_bool_r("", "hello world")) == "unknown"

    def test_family_takes_priority_over_regex(self):
        # family가 _true suffix인데 payload에 1=2 포함 → family 우선
        r = make_bool_r("and_int_true", " AND 1=2 -- ")
        assert _bool_classify(r) == "true"

    def test_or_family_priority_over_false_regex(self):
        # family가 or_*_true인데 payload에 false 패턴 → family 우선
        r = make_bool_r("or_int_cmt_true", " AND 1=2 -- ")
        assert _bool_classify(r) == "or_true"


# ── _compare_bool ──────────────────────────────────────────────────────────────

class TestCompareBool:

    def _pos(self, body_len: int, payload: str = "TRUE") -> list:
        return [make_bool_r("and_int_cmt_true", payload, "A" * body_len)]

    def _false(self, body_len: int, payload: str = "FALSE") -> list:
        return [make_bool_r("and_int_cmt_false", payload, "B" * body_len)]

    def test_confirmed_when_diff_over_5pct(self):
        conf, ev, _ = _compare_bool(self._pos(2000), self._false(100), "true")
        assert conf == "confirmed"

    def test_candidate_when_no_diff_no_error(self):
        conf, ev, _ = _compare_bool(self._pos(500), self._false(510), "true")
        assert conf == "candidate"

    def test_empty_pos_returns_none(self):
        assert _compare_bool([], self._false(100), "true") is None

    def test_empty_false_returns_none(self):
        assert _compare_bool(self._pos(100), [], "true") is None

    # [회귀 Round5] pos_items에 DB 에러 있으면 suspected
    # 주의: diff < 5% 보장 필요 — body 크기를 맞추지 않으면 confirmed로 판정됨
    def test_suspected_when_pos_has_db_error(self):
        error_suffix = "you have an error in your sql syntax"
        padding = "x" * 500
        pos = [make_bool_r("and_int_cmt_true", "", error_suffix + padding)]   # ~536자
        false_ = [make_bool_r("and_int_cmt_false", "", "y" * 536)]            # 536자, diff=0%
        conf, ev, _ = _compare_bool(pos, false_, "true")
        assert conf == "suspected"
        assert "DB 에러" in ev

    # [회귀 Round6 Fix2] false_items에 DB 에러 있어도 suspected로 올라와야 함
    def test_suspected_when_false_has_db_error(self):
        error_suffix = "you have an error in your sql syntax"
        padding = "x" * 500
        pos = [make_bool_r("and_int_cmt_true", "", "y" * 536)]                # 536자, diff=0%
        false_ = [make_bool_r("and_int_cmt_false", "", error_suffix + padding)]  # ~536자
        conf, ev, _ = _compare_bool(pos, false_, "true")
        assert conf == "suspected"
        assert "DB 에러" in ev

    # [회귀 Round6 Fix2] suspected일 때 대표 best는 pos_items여야 함 (false payload가 아님)
    def test_suspected_best_is_from_pos_not_false(self):
        pos = [make_bool_r("and_int_cmt_true", "TRUE_PAYLOAD", "normal" * 10)]
        false_ = [make_bool_r("and_int_cmt_false", "FALSE_PAYLOAD", "you have an error in your sql syntax")]
        _, _, best = _compare_bool(pos, false_, "true")
        assert best["payload"] == "TRUE_PAYLOAD"

    def test_confirmed_direction_label_positive(self):
        conf, ev, _ = _compare_bool(self._pos(2000), self._false(100), "true")
        assert "true>false" in ev

    def test_confirmed_direction_label_negative(self):
        # false가 더 크면 true<false
        conf, ev, _ = _compare_bool(self._pos(100), self._false(2000), "true")
        assert "true<false" in ev

    def test_or_true_label_in_evidence(self):
        pos = [make_bool_r("or_int_cmt_true", "", "A" * 2000)]
        false_ = self._false(100)
        _, ev, _ = _compare_bool(pos, false_, "or_true")
        assert "or_true" in ev


# ── _detect_boolean ────────────────────────────────────────────────────────────

class TestDetectBoolean:

    def test_and_true_vs_false_confirmed(self):
        group = [
            make_bool_r("and_int_cmt_true", "", "A" * 2000),
            make_bool_r("and_int_cmt_false", "", "B" * 100),
        ]
        hit = _detect_boolean(group)
        assert hit is not None and hit[0] == "confirmed"

    def test_and_true_vs_false_candidate_when_no_diff(self):
        group = [
            make_bool_r("and_int_cmt_true", "", "A" * 500),
            make_bool_r("and_int_cmt_false", "", "B" * 510),
        ]
        hit = _detect_boolean(group)
        assert hit is not None and hit[0] in ("candidate", "suspected")

    # [회귀 Round3] OR_TRUE가 AND_TRUE avg 계산에 포함되면 diff 왜곡
    def test_or_true_excluded_from_and_true_avg(self):
        group = [
            make_bool_r("and_int_cmt_true", "", "A" * 500),    # AND_TRUE
            make_bool_r("or_int_cmt_true", "", "A" * 5000),    # OR_TRUE — 여기 포함되면 avg 왜곡
            make_bool_r("and_int_cmt_false", "", "B" * 510),   # AND_FALSE
        ]
        hit = _detect_boolean(group)
        # AND_TRUE(500) vs AND_FALSE(510) → diff 2% → candidate
        # OR_TRUE가 포함됐으면 avg=(500+5000)/2=2750 vs 510 → confirmed (잘못된 결과)
        assert hit is not None and hit[0] == "candidate"

    # OR_TRUE 폴백: AND_TRUE 없고 OR_TRUE + FALSE 있을 때
    def test_or_true_fallback_when_no_and_true(self):
        group = [
            make_bool_r("or_int_cmt_true", "", "A" * 2000),
            make_bool_r("and_int_cmt_false", "", "B" * 100),
        ]
        hit = _detect_boolean(group)
        assert hit is not None and hit[0] == "confirmed"
        assert "or_true" in hit[1]

    # false_items만 있으면 비교 기준 없음 → None
    def test_false_only_returns_none(self):
        group = [make_bool_r("and_int_cmt_false", "", "B" * 500)]
        assert _detect_boolean(group) is None

    # AND_TRUE만 있으면 candidate
    def test_true_only_returns_candidate(self):
        group = [make_bool_r("and_int_cmt_true", "", "A" * 500)]
        hit = _detect_boolean(group)
        assert hit is not None and hit[0] == "candidate"

    # unknown만 있으면 None
    def test_unknown_only_returns_none(self):
        group = [make_bool_r("", "hello world")]
        assert _detect_boolean(group) is None

    def test_and_true_preferred_over_or_true_when_both_exist(self):
        group = [
            make_bool_r("and_int_cmt_true", "", "A" * 2000),
            make_bool_r("or_int_cmt_true", "", "A" * 100),
            make_bool_r("and_int_cmt_false", "", "B" * 100),
        ]
        hit = _detect_boolean(group)
        assert hit is not None
        # AND_TRUE가 있으면 OR_TRUE 폴백 아닌 AND_TRUE 기준
        assert "or_true" not in hit[1]


# ── _detect_orderby ────────────────────────────────────────────────────────────

class TestDetectOrderby:

    def _ob(self, body: str) -> dict:
        return make_r(payload=" ASC -- ", payload_type="SQLI_ORDERBY", response_body=body)

    def test_confirmed_when_diff_over_10pct(self):
        group = [self._ob("A" * 3000), self._ob("B" * 100)]
        hit = _detect_orderby(group)
        assert hit is not None and hit[0] == "confirmed"

    def test_confirmed_with_unknown_column_error(self):
        group = [
            self._ob("unknown column 'x' in order clause"),
            self._ob("normal response"),
        ]
        hit = _detect_orderby(group)
        assert hit is not None and hit[0] == "confirmed"

    def test_candidate_when_no_diff(self):
        group = [self._ob("A" * 500), self._ob("B" * 510)]
        hit = _detect_orderby(group)
        assert hit is not None and hit[0] == "candidate"

    def test_single_item_candidate(self):
        hit = _detect_orderby([self._ob("only one response")])
        assert hit is not None and hit[0] == "candidate"

    def test_empty_group_returns_none(self):
        assert _detect_orderby([]) is None

    # [회귀 Round6 Fix1] group[0]에 에러 없고 group[1]에 에러 있을 때 db_note 포함
    # diff < 10% 보장: confirmed로 나가면 db_note가 evidence에 없음
    def test_db_error_in_second_item_detected(self):
        base = "x" * 500
        group = [
            self._ob(base),                                           # 500자, 에러 없음
            self._ob(base + "you have an error in your sql syntax"),  # ~536자, diff=6.7%
        ]
        hit = _detect_orderby(group)
        assert hit is not None and "DB 에러" in hit[1]

    # [회귀 Round6 Fix1] group[0]에만 에러 있는 경우도 탐지
    def test_db_error_in_first_item_detected(self):
        base = "x" * 500
        group = [
            self._ob(base + "ORA-00933: SQL command not properly ended"),  # ~541자
            self._ob(base),                                                  # 500자, diff=7.6%
        ]
        hit = _detect_orderby(group)
        assert hit is not None and "DB 에러" in hit[1]

    # Fix1 핵심: 이전 코드(group[0]만 체크)에서는 이 케이스가 db_note 없이 나왔음
    def test_db_error_only_in_non_first_item_was_missed_before_fix(self):
        base = "x" * 500
        group = [
            self._ob(base),  # 에러 없음 (이전 코드는 여기만 체크)
            self._ob(base),  # 에러 없음
            self._ob(base + "com.mysql.jdbc.exceptions: SQL error"),  # ~548자, diff=4.7%
        ]
        hit = _detect_orderby(group)
        assert hit is not None and "DB 에러" in hit[1]


# ── _find_sqli_single ─────────────────────────────────────────────────────────

class TestFindSqliSingle:

    def test_time_based_confirmed(self):
        r = make_r(elapsed=5.0, payload_type="SQLI_TIME_MYSQL")
        hit = _find_sqli_single(r)
        assert hit is not None
        assert hit[0] == "confirmed" and hit[1] == "time_based"

    def test_time_based_below_threshold_ignored(self):
        r = make_r(elapsed=3.0, payload_type="SQLI_TIME_MYSQL")
        hit = _find_sqli_single(r)
        assert hit is None

    def test_time_based_wrong_type_not_triggered(self):
        # elapsed 충분해도 SQLI_BOOLEAN이면 time-based 판정 안 함
        r = make_r(elapsed=6.0, payload_type="SQLI_BOOLEAN")
        hit = _find_sqli_single(r)
        assert hit is None or hit[1] != "time_based"

    def test_error_based_mysql(self):
        r = make_r(
            response_body="you have an error in your sql syntax near '1' at line 1",
            payload_type="SQLI_ERROR_META",
        )
        hit = _find_sqli_single(r)
        assert hit is not None
        assert hit[0] == "confirmed" and "MySQL" in hit[2]

    def test_error_based_oracle(self):
        r = make_r(
            response_body="ORA-00933: SQL command not properly ended",
            payload_type="SQLI_ERROR_META",
        )
        hit = _find_sqli_single(r)
        assert hit is not None and hit[0] == "confirmed"

    def test_union_based_method(self):
        r = make_r(
            response_body="each UNION query must have the same number of columns",
            payload_type="SQLI_UNION",
        )
        hit = _find_sqli_single(r)
        assert hit is not None
        assert hit[0] == "confirmed" and hit[1] == "union_based"

    def test_http500_error_meta_suspected(self):
        r = make_r(status=500, payload_type="SQLI_ERROR_META", response_body="Internal Server Error")
        hit = _find_sqli_single(r)
        assert hit is not None and hit[0] == "suspected"

    def test_http500_wrong_type_not_suspected(self):
        # 500이지만 SQLI_BOOLEAN이면 suspected 아님
        r = make_r(status=500, payload_type="SQLI_BOOLEAN", response_body="error")
        hit = _find_sqli_single(r)
        assert hit is None


# ── _find_xss ─────────────────────────────────────────────────────────────────

class TestFindXss:

    def test_onerror_marker_confirmed(self):
        r = make_r(response_body='<img src=x onerror=alert(1)>', payload='<img src=x onerror=alert(1)>')
        hit = _find_xss(r)
        assert hit is not None and hit[0] == "confirmed"

    def test_script_alert_marker_confirmed(self):
        r = make_r(response_body='output: <script>alert(1)</script>', payload='<script>alert(1)</script>')
        hit = _find_xss(r)
        assert hit is not None and hit[0] == "confirmed"

    def test_encoded_lt_gt_not_confirmed(self):
        r = make_r(
            response_body='result: &lt;img src=x onerror=alert(1)&gt;',
            payload='<img src=x onerror=alert(1)>',
        )
        hit = _find_xss(r)
        assert hit is None or hit[0] != "confirmed"

    def test_plain_payload_reflection_suspected(self):
        # 마커 없는 단순 문자열이 body에 반사됨 → suspected
        r = make_r(
            response_body='search result for: xss_probe_token_abc',
            payload='xss_probe_token_abc',
        )
        hit = _find_xss(r)
        assert hit is not None and hit[0] == "suspected"

    def test_no_reflection_no_hit(self):
        r = make_r(response_body='welcome to the homepage', payload='xss_probe_token_abc')
        hit = _find_xss(r)
        assert hit is None

    def test_short_payload_not_reflected(self):
        # 3자 이하 payload는 suspected 판정 안 함 (len >= 4 조건)
        r = make_r(response_body='abc abc abc', payload='abc')
        hit = _find_xss(r)
        assert hit is None

    def test_empty_body_returns_none(self):
        r = make_r(response_body='', payload='<script>alert(1)</script>')
        hit = _find_xss(r)
        assert hit is None

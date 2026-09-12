from __future__ import annotations

import unittest

from analyzer import family_pipeline
from analyzer.headless import HeadlessVerdict

PAYLOAD = "<script>alert(1)</script>"


class _FakeHeadless:  # 실제 브라우저 없이 navigate 발화 여부를 고정값으로 흉내
    def __init__(self, executed: bool):
        self.executed = executed

    def confirm_via_navigate(self, url, cookies, method) -> HeadlessVerdict:
        return HeadlessVerdict(executed=self.executed, method="navigate", evidence="fake")


def _family(sink_confirmed: bool = True) -> dict:
    return {
        "family_id": "t0_msg_PL-XSS-STORED", "target_id": "t0", "param": "msg",
        "attack_id": "PL-XSS-STORED", "technique": "stored",
        "sink_confirmed": sink_confirmed,
    }


def _case(payload: str, before: str, after: str) -> dict:
    return {
        "case": {"case_id": "c0", "payload": payload, "url": "http://x/list", "method": "GET"},
        "status": "ok",
        "before_revisit_body": before,
        "revisit_body": after,
        "revisit_url_used": "http://x/list",
        "effective_cookies": {},
    }


class StoredJudgeTests(unittest.TestCase):
    """§3.4 판정표 6분기를 _judge_stored 단위로 검증."""

    def test_sink_unconfirmed_is_inconclusive(self) -> None:
        # Phase 1 sink 미확인 → inconclusive
        finding = family_pipeline._judge_stored(
            _family(sink_confirmed=False), _case(PAYLOAD, "", PAYLOAD), _FakeHeadless(False))
        self.assertEqual(finding.final_status, "inconclusive")

    def test_payload_not_in_revisit_is_inconclusive(self) -> None:
        # Phase 2 재조회에 payload 끝내 안 뜸(N회 실패) → inconclusive
        finding = family_pipeline._judge_stored(
            _family(), _case(PAYLOAD, "base", "base only, no payload"), _FakeHeadless(False))
        self.assertEqual(finding.final_status, "inconclusive")

    def test_residue_only_is_safe(self) -> None:
        # payload가 before/after 둘 다 있음(잔재) → diff 새 영역 없음 → safe
        body = "line1\n" + PAYLOAD
        finding = family_pipeline._judge_stored(
            _family(), _case(PAYLOAD, body, body), _FakeHeadless(False))
        self.assertEqual(finding.final_status, "safe")

    def test_new_region_without_payload_is_safe(self) -> None:
        # payload는 잔재(before), 새 영역엔 noise만 → raw hit 없음 → safe
        before = "line1\n" + PAYLOAD
        after = before + "\n<p>just noise</p>"
        finding = family_pipeline._judge_stored(
            _family(), _case(PAYLOAD, before, after), _FakeHeadless(False))
        self.assertEqual(finding.final_status, "safe")

    def test_new_region_with_payload_not_executed_is_reflected_only(self) -> None:
        # 실제 저장 + raw hit + navigate 미발화 → reflected_only
        finding = family_pipeline._judge_stored(
            _family(), _case(PAYLOAD, "line1", "line1\n" + PAYLOAD), _FakeHeadless(executed=False))
        self.assertEqual(finding.final_status, "reflected_only")

    def test_new_region_with_payload_executed_is_vulnerable(self) -> None:
        # 실제 저장 + raw hit + navigate 발화 → vulnerable
        finding = family_pipeline._judge_stored(
            _family(), _case(PAYLOAD, "line1", "line1\n" + PAYLOAD), _FakeHeadless(executed=True))
        self.assertEqual(finding.final_status, "vulnerable")


if __name__ == "__main__":
    unittest.main()

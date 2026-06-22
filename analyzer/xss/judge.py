from __future__ import annotations

from dataclasses import dataclass


@dataclass
class XssVerdict:
    vulnerable: bool
    confidence: str
    evidence: str


def judge_xss(response_body: str, payload: str) -> XssVerdict:
    body = response_body or ""
    # payload가 HTML 이스케이프 없이 그대로 반사되면 XSS
    # 이스케이프된 경우(&lt;script&gt;)는 payload의 '<'와 달라서 매칭 안 됨
    if payload.lower() in body.lower():
        return XssVerdict(True, "high", f"XSS: payload가 응답에 비이스케이프 상태로 반사됨")
    return XssVerdict(False, "", "XSS payload 반사 없음")

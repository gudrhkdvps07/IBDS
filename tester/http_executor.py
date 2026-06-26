import hashlib
import httpx

_TEXT_PREFIXES = ("text/", "application/json", "application/xml", "application/javascript")  # body_preview 저장 대상 content-type
_SUPPORTED_BODY_TYPES = (None, "form", "json")  # 지원하는 body_type 목록

_STORE_DISABLED = {"body_saved": False, "body_path": None, "body_save_reason": "response store disabled"}


# 텍스트 응답 여부 판별
def _is_text(content_type: str) -> bool:
    ct = content_type.split(";")[0].strip()
    return any(ct.startswith(p) for p in _TEXT_PREFIXES)


class HttpExecutor:
    def __init__(self, response_store=None):
        self._clients: dict[str, httpx.Client] = {}
        self._store = response_store  # HtmlResponseStore 또는 None

    # role별 클라이언트 조회 또는 생성
    def _get_client(self, role: str) -> httpx.Client:
        if role not in self._clients:
            self._clients[role] = httpx.Client(
                follow_redirects=True,
                timeout=10,
                verify=True,
            )
        return self._clients[role]

    # test case 실행 및 결과 반환 (skipped/error/성공 모두 동일 구조)
    def execute(self, case: dict) -> dict:
        role = case.get("role") or "default"
        method = case["method"]
        url = case["url"]
        headers = case.get("headers") or None
        cookies = case.get("cookies") or None
        body_type = case.get("body_type")
        body = case.get("body")

        # 헤더·쿠키 값은 결과에 포함하지 않고 존재 여부·이름만 기록
        request_summary = {
            "method": method,
            "url": url,
            "body_type": body_type,
            "has_headers": bool(headers),
            "header_names": list(headers.keys()) if headers else [],
            "has_cookies": bool(cookies),
            "has_body": body is not None,
        }

        base = {
            "case_id": case.get("case_id"),
            "target_id": case.get("target_id"),
            "test_type": case.get("test_type"),
            "engine": case.get("engine"),
            "role": role,
            "request": request_summary,
        }

        if body_type not in _SUPPORTED_BODY_TYPES:  # 미지원 body_type skipped 처리
            return {**base, "response": None, "error": None,
                    "skipped": True, "skip_reason": f"unsupported body_type: {body_type!r}"}

        client = self._get_client(role)
        kwargs: dict = dict(
            params=case.get("query") or None,
            headers=headers,
            cookies=cookies,
        )
        if body_type == "form":  # body_type에 따라 전송 방식 분기
            kwargs["data"] = body
        elif body_type == "json":
            kwargs["json"] = body

        try:
            resp = client.request(method, url, **kwargs)
            content_type = resp.headers.get("content-type", "")

            store_result = (
                self._store.save(case.get("case_id", ""), content_type, resp.content)
                if self._store else _STORE_DISABLED
            )

            return {
                **base,
                "response": {
                    "status_code": resp.status_code,
                    "final_url": str(resp.url),  # 리다이렉트 후 최종 URL
                    "content_type": content_type,
                    "content_length_header": resp.headers.get("content-length"),
                    "location": resp.headers.get("location"),
                    "set_cookie_present": "set-cookie" in resp.headers,
                    "server": resp.headers.get("server"),
                    "redirect_count": len(resp.history),
                    "is_text_response": _is_text(content_type),
                    "body_length": len(resp.content),
                    "body_hash": hashlib.sha256(resp.content).hexdigest(),  # raw response body SHA-256
                    "body_preview": resp.text[:1000] if _is_text(content_type) else None,  # 텍스트 응답만 앞 1000자 저장
                    "body_saved": store_result["body_saved"],
                    "body_path": store_result["body_path"],
                    "body_save_reason": store_result["body_save_reason"],
                    "elapsed_ms": round(resp.elapsed.total_seconds() * 1000),
                },
                "error": None,
            }
        except Exception as e:
            return {**base, "response": None, "error": str(e)}

    # 모든 role 클라이언트 종료
    def close(self):
        for c in self._clients.values():
            c.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

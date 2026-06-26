import hashlib
import httpx

_TEXT_PREFIXES = ("text/", "application/json", "application/xml", "application/javascript")
_SUPPORTED_BODY_TYPES = (None, "form", "json")


def _is_text(content_type: str) -> bool:
    ct = content_type.split(";")[0].strip()
    return any(ct.startswith(p) for p in _TEXT_PREFIXES)


class HttpExecutor:
    def __init__(self):
        self._clients: dict[str, httpx.Client] = {}

    def _get_client(self, role: str) -> httpx.Client:
        if role not in self._clients:
            self._clients[role] = httpx.Client(
                follow_redirects=True,
                timeout=10,
                verify=True,
            )
        return self._clients[role]

    def execute(self, case: dict) -> dict:
        role = case.get("role") or "default"
        method = case["method"]
        url = case["url"]
        headers = case.get("headers") or None
        cookies = case.get("cookies") or None
        body_type = case.get("body_type")
        body = case.get("body")

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

        if case.get("engine") != "http":
            return {**base, "response": None, "error": None,
                    "skipped": True, "skip_reason": f"unsupported engine: {case.get('engine')!r}"}

        if body_type not in _SUPPORTED_BODY_TYPES:
            return {**base, "response": None, "error": None,
                    "skipped": True, "skip_reason": f"unsupported body_type: {body_type!r}"}

        client = self._get_client(role)
        kwargs: dict = dict(
            params=case.get("query") or None,
            headers=headers,
            cookies=cookies,
        )
        if body_type == "form":
            kwargs["data"] = body
        elif body_type == "json":
            kwargs["json"] = body

        try:
            resp = client.request(method, url, **kwargs)
            content_type = resp.headers.get("content-type", "")
            return {
                **base,
                "response": {
                    "status_code": resp.status_code,
                    "final_url": str(resp.url),
                    "content_type": content_type,
                    "content_length_header": resp.headers.get("content-length"),
                    "location": resp.headers.get("location"),
                    "set_cookie_present": "set-cookie" in resp.headers,
                    "server": resp.headers.get("server"),
                    "redirect_count": len(resp.history),
                    "is_text_response": _is_text(content_type),
                    "body_length": len(resp.content),
                    "body_hash": hashlib.sha256(resp.content).hexdigest(),
                    "body_preview": resp.text[:500] if _is_text(content_type) else None,
                    "elapsed_ms": round(resp.elapsed.total_seconds() * 1000),
                },
                "error": None,
            }
        except Exception as e:
            return {**base, "response": None, "error": str(e)}

    def close(self):
        for c in self._clients.values():
            c.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

import json
import os
import sys
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse
from mitmproxy import http

# proxy/ 하위에 있으므로 프로젝트 루트를 sys.path에 추가 -> core 같은 패키지를 import하기 위함.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from core.session_context import (
    create_new_capture,
    get_capture_dir,
    get_proxy_history_path,
)


# 캡처에서 제외할 정적 파일 확장자
_STATIC_EXTENSIONS = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".svg",
    ".map", ".webp", ".bmp", ".pdf", ".zip",
)

# 브라우저 잡다한 트래픽 호스트 (정확히 일치해야함)
_JUNK_HOSTS = {
    "detectportal.firefox.com",
    "safebrowsing.googleapis.com",
    "push.services.mozilla.com",
    "updates.push.services.mozilla.com",
    "normandy.cdn.mozilla.net",
    "incoming.telemetry.mozilla.org",
    "content-signature.cdn.mozilla.net",
    "shavar.services.mozilla.com",
}

# 브라우저 잡트래픽 호스트 suffix (endswith 비교)
_JUNK_HOST_SUFFIXES = (
    ".firefox.com",
    ".mozilla.com",
    ".mozilla.net",
    ".mozilla.org",
    ".google-analytics.com",
    ".googletagmanager.com",
    ".doubleclick.net",
)


def _is_static(path: str) -> bool:
    bare = path.split("?")[0].lower()
    return any(bare.endswith(ext) for ext in _STATIC_EXTENSIONS)


def _is_junk_host(host: str) -> bool:
    h = host.lower()
    return h in _JUNK_HOSTS or any(h.endswith(s) for s in _JUNK_HOST_SUFFIXES)


def _parse_cookies(cookie_header: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for part in cookie_header.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            cookies[k.strip()] = v.strip()
    return cookies


def _params_as_list(qs: str) -> list[dict[str, str]]:
    result = []
    for name, values in parse_qs(qs, keep_blank_values=True).items():
        for value in values:
            result.append({"name": name, "value": value})
    return result


class CaptureAddon:
    def __init__(self) -> None:
        self._capture_id = create_new_capture()
        os.makedirs(get_capture_dir(self._capture_id), exist_ok=True)
        self._output_file = get_proxy_history_path(self._capture_id)
        print(f"[capture] capture_id={self._capture_id}")
        print(f"[capture] → {self._output_file}")

    def request(self, flow: http.HTTPFlow) -> None:
        req = flow.request

        if _is_junk_host(req.host):
            return
        if _is_static(req.path):
            return

        parsed = urlparse(req.pretty_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        parameters = _params_as_list(parsed.query)

        content_type = req.headers.get("content-type", "")
        body = ""
        if req.method == "POST":
            try:
                body = req.text
            except Exception:
                pass
            if "application/x-www-form-urlencoded" in content_type:
                try:
                    parameters += _params_as_list(body)
                except Exception:
                    pass

        cookies = _parse_cookies(req.headers.get("cookie", ""))

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": req.method,
            "scheme": parsed.scheme,
            "host": req.host,
            "port": req.port,
            "path": parsed.path,
            "full_url": req.pretty_url,
            "base_url": base_url,
            "parameters": parameters,
            "content_type": content_type,
            "body": body,
            "cookies": cookies,
            "headers": dict(req.headers),
        }

        with open(self._output_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

        print(f"[capture] {req.method} {req.pretty_url}  params={len(parameters)}")


addons = [CaptureAddon()]

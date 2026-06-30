import json
import os
import httpx

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_CONFIG = os.path.join(_PROJECT_ROOT, "config", "zap_config.json")


def _load_config(path=_DEFAULT_CONFIG):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


class ZapClient:
    def __init__(self, host="127.0.0.1", port=8080, api_key=""):
        self._base = f"http://{host}:{port}"
        self._api_key = api_key
        self._http = httpx.Client(timeout=10)

    @classmethod
    def from_config(cls, path=_DEFAULT_CONFIG):
        cfg = _load_config(path)
        return cls(
            host=cfg.get("host", "127.0.0.1"),
            port=cfg.get("port", 8080),
            api_key=cfg.get("api_key", ""),
        )

    def _params(self, **kwargs):
        p = {k: v for k, v in kwargs.items() if v is not None}
        if self._api_key:
            p["apikey"] = self._api_key
        return p

    def _get(self, path, **kwargs):
        r = self._http.get(f"{self._base}{path}", params=self._params(**kwargs))
        r.raise_for_status()
        return r.json()

    # ZAP 메시지 1페이지 조회
    def get_messages(self, base_url=None, start=0, count=200) -> list[dict]:
        return self._get(
            "/JSON/core/view/messages/",
            baseurl=base_url, start=start, count=count,
        ).get("messages", [])

    # 전체 메시지 조회 (페이지네이션 자동 처리)
    def get_all_messages(self, base_url=None, page_size=200) -> list[dict]:
        all_msgs, start = [], 0
        while True:
            batch = self.get_messages(base_url=base_url, start=start, count=page_size)
            all_msgs.extend(batch)
            if len(batch) < page_size:
                break
            start += page_size
        return all_msgs

    def close(self):
        self._http.close()

    def __enter__(self): return self
    def __exit__(self, *_): self.close()

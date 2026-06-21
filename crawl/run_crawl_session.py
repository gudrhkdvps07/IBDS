"""
크롤 세션 실행부

target_config 읽어서 인증 크롤링 실행
크롤 결과 저장, proxy snapshot 생성
"""
import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

from utilities.file_utils import load_json
from crawl.crawler import Crawler
from authentication.auth import get_auth_cookies
from core.session_context import (
    get_or_create_current_capture,
    get_proxy_history_path,
    create_session_id,
    get_session_dir,
    snapshot_proxy_history,
    save_session_meta,
)

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_BASE_DIR)
_DEFAULT_CONFIG_PATH = os.path.join(_PROJECT_ROOT, "config", "target_config.json")


# 크롤 세션 실행 및 정보 반환
def run_crawl_session(config_path: str | None = None, with_proxy: bool = True) -> dict:
    config_path = config_path or _DEFAULT_CONFIG_PATH
    config = load_json(config_path, {})
    base_url = config.get("target_url", os.getenv("TARGET_URL", "http://localhost:8080"))
    auth_cfg = config.get("auth", {})

    auth_cookies = get_auth_cookies(auth_cfg, base_url=base_url) or None

    capture_id = get_or_create_current_capture() if with_proxy else None
    session_id = create_session_id()
    session_dir = get_session_dir(session_id)
    os.makedirs(session_dir, exist_ok=True)

    print(f"[SESSION] {session_id}  (capture: {capture_id})")

    roles = [
        ("guest",  None),
        ("member", auth_cookies),
    ]

    started_at = datetime.now(timezone.utc).isoformat()
    all_results: list[dict] = []

    for role, cookies in roles:
        if role == "member" and not cookies:
            print(f"[CRAWL] auth 설정 없음, member 크롤링 생략")
            continue

        print(f"\n[CRAWL] === {role} 크롤링 시작 ===")
        crawler = Crawler(
            base_url,
            init_cookies=cookies,
            skip_auth=(role == "guest"),
        )
        crawler.crawl()
        crawler.summary()
        for r in crawler.results:
            r.role = role
        all_results.extend(asdict(r) for r in crawler.results)

    output_file = os.path.join(session_dir, "crawl_result.json")
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(all_results, f, ensure_ascii=False, indent=2)
    print(f"[CRAWL] saved: {output_file}")

    finished_at = datetime.now(timezone.utc).isoformat()

    if with_proxy:
        from proxy.capture_config import build_proxy_url, _load_proxy_config
        proxy_cfg = _load_proxy_config()
        proxy_host = proxy_cfg.get("host", "127.0.0.1")
        proxy_port = proxy_cfg.get("port", 8081)
        proxy_enabled = bool(build_proxy_url())
    else:
        proxy_host, proxy_port, proxy_enabled = "127.0.0.1", 8081, False

    meta = {
        "session_id": session_id,
        "capture_id": capture_id,
        "target_url": base_url,
        "proxy": {
            "enabled": proxy_enabled,
            "host": proxy_host,
            "port": proxy_port,
        },
        "started_at": started_at,
        "finished_at": finished_at,
    }
    meta_path = save_session_meta(session_dir, meta)
    print(f"[SESSION] meta → {meta_path}")

    snapshot_path = os.path.join(session_dir, "proxy_history_snapshot.jsonl")
    if with_proxy and capture_id:
        source_path = get_proxy_history_path(capture_id)
        snapshot_proxy_history(
            source_path=source_path,
            output_path=snapshot_path,
            target_url=base_url,
            started_at=started_at,
            finished_at=finished_at,
        )
    else:
        open(snapshot_path, "w").close()
        print(f"[SESSION] proxy 없음 → 빈 snapshot 생성: {snapshot_path}")

    return {
        "session_id": session_id,
        "session_dir": session_dir,
        "capture_id": capture_id,
        "target_url": base_url,
    }


if __name__ == "__main__":
    run_crawl_session(with_proxy=True)

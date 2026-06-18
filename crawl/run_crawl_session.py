"""
크롤 세션 실행부

target_config 읽어서 인증 크롤링 실행
크롤 결과 저장, proxy snapshot 생성
"""
import os
from dotenv import load_dotenv

load_dotenv()

from utilities.file_utils import load_json
from crawl.crawler import Crawler
from authentication.auth import get_auth_cookies
from core.session_context import (
    get_or_create_current_capture,
    create_session_id,
    get_session_dir,
    snapshot_proxy_history,
)

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TARGET_CONFIG_PATH = os.path.join(_BASE_DIR, "..", "target_config.json")

if __name__ == "__main__":
    # target_config.json의 대상 URL과 인증 설정 로드
    config = load_json(TARGET_CONFIG_PATH, {})
    base_url = config.get("target_url", os.getenv("TARGET_URL", "http://localhost:8080"))
    auth_cfg = config.get("auth", {})

    # 인증 쿠키 획득 결과
    auth_cookies = get_auth_cookies(auth_cfg, base_url=base_url) or None

    # mitmproxy가 생성한 현재 capture 식별자
    capture_id = get_or_create_current_capture()
    # 이번 크롤링 실행 단위 session 생성
    session_id = create_session_id()
    session_dir = get_session_dir(session_id)
    os.makedirs(session_dir, exist_ok=True)

    print(f"[SESSION] {session_id}  (capture: {capture_id})")

    roles = [
        ("guest",  None),
        ("member", auth_cookies),
    ]

    for role, cookies in roles: # member가 있으면 member, guest 두번 크롤
        if role == "member" and not cookies:
            print(f"[CRAWL] auth 설정 없음, member 크롤링 생략")
            continue

        print(f"\n[CRAWL] === {role} 크롤링 시작 ===")
        output_file = os.path.join(session_dir, f"crawl_result_{role}.json")  # session 폴더 저장

        crawler = Crawler(base_url, init_cookies=cookies)
        crawler.crawl()
        crawler.save(output_file)
        crawler.summary()

    # 크롤링 종료 후 현재 proxy_history.jsonl의 session 폴더 복사
    history_path = snapshot_proxy_history(capture_id, session_id)
    print(f"[SESSION] snapshot -> {history_path}")

"""
데모 크롤러 실행부

실행 전 준비:
  터미널 1: mitmdump -s proxy/capture.py -p 8081
  터미널 2: python -m crawl.poc_capture

target_config.json에서 대상 URL과 인증 정보를 읽음
비로그인(guest) -> 로그인(member) 순서로 각각 크롤링
"""


import os
from dotenv import load_dotenv

load_dotenv()

from utilities import load_json
from crawl.crawler import Crawler, _RUN_TS
from authentication.auth import get_auth_cookies

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TARGET_CONFIG_PATH = os.path.join(_BASE_DIR, "..", "target_config.json")

if __name__ == "__main__":
    config = load_json(TARGET_CONFIG_PATH, {})
    base_url = config.get("target_url", os.getenv("TARGET_URL", "http://localhost:8080"))
    auth_cfg = config.get("auth", {})

    auth_cookies = get_auth_cookies(auth_cfg, base_url=base_url) or None

    _results_dir = os.path.join(_BASE_DIR, "..", "results")
    os.makedirs(_results_dir, exist_ok=True)
    with open(os.path.join(_results_dir, ".run_id"), "w") as f:
        f.write(_RUN_TS)

    roles = [
        ("guest",  None),
        ("member", auth_cookies),
    ]

    for role, cookies in roles:
        if role == "member" and not cookies:
            print(f"[CRAWL] auth 설정 없음, member 크롤링 생략")
            continue

        print(f"\n[CRAWL] === {role} 크롤링 시작 ===")
        output_file = f"results/run_{_RUN_TS}/crawl_result_{role}.json"

        crawler = Crawler(base_url, init_cookies=cookies)
        crawler.crawl()
        crawler.save(output_file)
        crawler.summary()

"""
DVWA PoC용 크롤러 실행 스크립트.

실행 전 준비:
  터미널 1: mitmdump -s proxy/capture.py -p 8081
  터미널 2: 아래 환경변수 설정 후 python -m crawl.poc_capture

환경변수:
  TARGET_URL           = http://localhost:8080
  PROXY_URL            = http://127.0.0.1:8081
  DEMO_DVWA_AUTH       = 1
  DEMO_DVWA_PHPSESSID  = <브라우저에서 복사한 값>
"""
import os
from dotenv import load_dotenv

load_dotenv()

from crawl.crawler import Crawler, BASE_URL, OUTPUT_FILE, _RUN_TS
from authentication.auth import get_demo_dvwa_cookies

if __name__ == "__main__":
    # 프록시에 새 크롤 세션 시작을 알림
    _results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results")
    os.makedirs(_results_dir, exist_ok=True)
    with open(os.path.join(_results_dir, ".run_id"), "w") as f:
        f.write(_RUN_TS)

    init_cookies = get_demo_dvwa_cookies() or None

    crawler = Crawler(BASE_URL, init_cookies=init_cookies)
    crawler.crawl()
    crawler.save(OUTPUT_FILE)
    crawler.summary()

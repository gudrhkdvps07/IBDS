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

from crawl.crawler import Crawler, BASE_URL, OUTPUT_FILE
from authentication.auth import get_demo_dvwa_cookies

if __name__ == "__main__":
    init_cookies = get_demo_dvwa_cookies() or None

    crawler = Crawler(BASE_URL, init_cookies=init_cookies)
    crawler.crawl(extra_seeds=[
        f"{BASE_URL}/vulnerabilities/sqli/?id=1&Submit=Submit",
        f"{BASE_URL}/vulnerabilities/xss_r/?name=test",
    ])
    crawler.save(OUTPUT_FILE)
    crawler.summary()

import os
from dotenv import load_dotenv

load_dotenv()


# 크롤링 실행값 환경변수 설정
class CrawlConfig:
    MAX_PAGES = int(os.getenv("CRAWL_MAX_PAGES", "500"))
    MIN_PAGES = int(os.getenv("CRAWL_MIN_PAGES", "100"))
    STAGNATION_LIMIT = int(os.getenv("CRAWL_STAGNATION_LIMIT", "50"))
    DELAY = float(os.getenv("CRAWL_DELAY", "0.3"))
    TIMEOUT = int(os.getenv("CRAWL_TIMEOUT", "10"))


# 방문 대상에서 제외할 URL 패턴 목록
EXCLUDE_PATTERNS = [
    r"logout",
    r"signout",
    r"\.(jpg|jpeg|png|gif|svg|ico|css|js|pdf|zip|woff|ttf|eot)(\?|$)",
]

# GET 요청만으로 데이터 변경 가능성이 있는 URL 패턴 목록
DANGER_LINK_PATTERNS = [
    r"delete",
    r"remove",
    r"move",
    r"copy",
    r"update",
    r"modify",
    r"write_update",
    r"comment_update",
    r"file_delete",
    r"dbupgrade",
    r"truncate",
    r"drop",
    r"reset",
]

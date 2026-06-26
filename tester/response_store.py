import re
import shutil
from pathlib import Path

_HTML_TYPES = ("text/html", "application/xhtml+xml")  # HTML 저장 대상 content-type
_SAFE_RE = re.compile(r"[^\w\-.]")  # 파일명 비허용 문자 치환용 패턴


# case_id를 파일명 안전 문자로 변환
def _safe_filename(case_id: str) -> str:
    return _SAFE_RE.sub("_", case_id)


class HtmlResponseStore:
    # html_dir 초기화 (기존 디렉터리 삭제 후 재생성)
    def __init__(self, html_dir: Path):
        self._html_dir = html_dir
        if self._html_dir.exists():
            shutil.rmtree(self._html_dir)  # 이전 실행 결과 초기화
        self._html_dir.mkdir(parents=True)

    # HTML 응답이면 파일 저장 후 결과 반환, 아니면 저장 없이 이유 반환
    def save(self, case_id: str, content_type: str, body: bytes) -> dict:
        ct = content_type.split(";")[0].strip()
        if ct not in _HTML_TYPES:
            return {"body_saved": False, "body_path": None, "body_save_reason": "non-html response"}

        filename = _safe_filename(case_id) + ".html"
        (self._html_dir / filename).write_bytes(body)
        return {
            "body_saved": True,
            "body_path": str(self._html_dir / filename),  # 프로젝트 루트 기준 경로
            "body_save_reason": None,
        }

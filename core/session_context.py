import os
import shutil
from datetime import datetime

# 프로젝트 루트 기준으로 경로 계산 (core/ 한 단계 위)
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_RESULTS_DIR = os.path.join(_PROJECT_ROOT, "results")
_CURRENT_CAPTURE_FILE = os.path.join(_RESULTS_DIR, ".current_capture")  # 현재 활성 capture_id 저장 파일


# 프로젝트 루트 경로 반환
def get_project_root() -> str:
    return _PROJECT_ROOT


# capture_YYYYMMDD_HHMMSS 형식의 capture ID 생성
def create_capture_id() -> str:
    return "capture_" + datetime.now().strftime("%Y%m%d_%H%M%S")


# 새 capture를 시작하고 .current_capture에 덮어씀
# mitmproxy 시작 시 호출 → 항상 새 capture 폴더로 분리됨
def create_new_capture() -> str:
    os.makedirs(_RESULTS_DIR, exist_ok=True)
    capture_id = create_capture_id()
    with open(_CURRENT_CAPTURE_FILE, "w") as f:
        f.write(capture_id)
    return capture_id


# 현재 활성 capture_id 반환. 없으면 새로 생성
# 크롤 실행 시 호출 → mitmproxy가 만들어둔 capture를 그대로 이어 사용
def get_or_create_current_capture() -> str:
    os.makedirs(_RESULTS_DIR, exist_ok=True)
    try:
        with open(_CURRENT_CAPTURE_FILE) as f:
            capture_id = f.read().strip()
        if capture_id:
            return capture_id
    except FileNotFoundError:
        pass
    return create_new_capture()


# capture 폴더 경로 반환: results/captures/<capture_id>/
def get_capture_dir(capture_id: str) -> str:
    return os.path.join(_RESULTS_DIR, "captures", capture_id)


# proxy_history.jsonl 파일 경로 반환
def get_proxy_history_path(capture_id: str) -> str:
    return os.path.join(get_capture_dir(capture_id), "proxy_history.jsonl")


# session_YYYYMMDD_HHMMSS 형식의 session ID 생성
def create_session_id() -> str:
    return "session_" + datetime.now().strftime("%Y%m%d_%H%M%S")


# session 폴더 경로 반환: results/sessions/<session_id>/
def get_session_dir(session_id: str) -> str:
    return os.path.join(_RESULTS_DIR, "sessions", session_id)


# capture의 proxy_history.jsonl을 session 폴더에 복사 (스냅샷)
# 크롤 종료 후 호출해 해당 시점까지의 트래픽을 session에 묶어 보관
def snapshot_proxy_history(capture_id: str, session_id: str) -> str:
    src = get_proxy_history_path(capture_id)
    dst_dir = get_session_dir(session_id)
    os.makedirs(dst_dir, exist_ok=True)
    dst = os.path.join(dst_dir, "proxy_history_history.jsonl")
    if os.path.exists(src):
        shutil.copy2(src, dst)
    else:
        print(f"[WARN] proxy_history 를 찾을 수 없음: {src} → 빈 history파일 생성됨")
        open(dst, "w").close()
    return dst

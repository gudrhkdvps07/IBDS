import json
import os
from datetime import datetime, timezone
from urllib.parse import urlparse

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_RESULTS_DIR = os.path.join(_PROJECT_ROOT, "results")
_CURRENT_CAPTURE_FILE = os.path.join(_RESULTS_DIR, ".current_capture")


def get_project_root() -> str:
    return _PROJECT_ROOT


def create_capture_id() -> str:
    return "capture_" + datetime.now().strftime("%Y%m%d_%H%M%S")


def create_new_capture() -> str:
    os.makedirs(_RESULTS_DIR, exist_ok=True)
    capture_id = create_capture_id()
    with open(_CURRENT_CAPTURE_FILE, "w") as f:
        f.write(capture_id)
    return capture_id


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


def get_capture_dir(capture_id: str) -> str:
    return os.path.join(_RESULTS_DIR, "captures", capture_id)


def get_proxy_history_path(capture_id: str) -> str:
    return os.path.join(get_capture_dir(capture_id), "proxy_history.jsonl")


def create_session_id() -> str:
    return "session_" + datetime.now().strftime("%Y%m%d_%H%M%S")


def get_session_dir(session_id: str) -> str:
    return os.path.join(_RESULTS_DIR, "sessions", session_id)


# 포트가 생략된 URL일 경우, http =80, https=443으로 채워주는 용도
def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


def snapshot_proxy_history(
    source_path: str,
    output_path: str,
    target_url: str,
    started_at: str,
    finished_at: str,
) -> None:

    target = urlparse(target_url)
    target_host = target.hostname or ""
    target_port = target.port or _default_port(target.scheme)
    target_scheme = target.scheme

    start_ts = _parse_ts(started_at)
    end_ts = _parse_ts(finished_at)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    matched = 0
    if not os.path.exists(source_path):
        print(f"[WARN] proxy_history를 찾을 수 없음: {source_path}")
        open(output_path, "w").close()
        return

    with open(source_path, encoding="utf-8") as src, open(output_path, "w", encoding="utf-8") as dst:
        for line in src:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            # scheme, host, port 가 target_url과 일치하는 부분만 저장
            if record.get("scheme") != target_scheme:
                continue
            if record.get("host") != target_host:
                continue
            if record.get("port") != target_port:
                continue
            
            # timestamp 가 started_at 이상 finished_at 이하인 부분만 저장
            ts_raw = record.get("timestamp")
            if not ts_raw:
                continue
            try:
                record_ts = _parse_ts(ts_raw)
            except ValueError:
                continue
            if not (start_ts <= record_ts <= end_ts):
                continue

            dst.write(json.dumps(record, ensure_ascii=False) + "\n")
            matched += 1

    print(f"[SESSION] snapshot → {output_path}  ({matched} records)")


def save_session_meta(session_dir: str, meta: dict) -> str:
    os.makedirs(session_dir, exist_ok=True)
    path = os.path.join(session_dir, "session_meta.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
    return path

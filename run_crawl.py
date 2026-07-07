from crawl.run_crawl_session import run_crawl_session
from pathlib import Path
from scanner.merge import merge
from utilities.file_utils import save_json

result = run_crawl_session(with_proxy=True)
session_dir = Path(result["session_dir"])

targets = merge(session_dir)
save_json(str(session_dir / "scan_targets.json"), targets)

scannable = sum(1 for t in targets if t["can_scan"])
print(f"\nsession_dir : {session_dir}")
print(f"targets     : {len(targets)}")
print(f"can_scan    : {scannable}")
print(f"skipped     : {len(targets) - scannable}")
print(f"저장        : {session_dir / 'scan_targets.json'}")

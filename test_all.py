"""
크롤 + merge 파이프라인 테스트 (프록시 없이)
"""
import json
from pathlib import Path

from crawl.run_crawl_session import run_crawl_session
from scanner.merge import merge
from utilities.file_utils import save_json


def main():
    # 1. 크롤 실행
    print("=" * 50)
    print("[PIPELINE] Step 1: 크롤 세션 실행")
    print("=" * 50)
    result = run_crawl_session(with_proxy=True)

    session_dir = Path(result["session_dir"])
    print(f"\n[PIPELINE] session_dir: {session_dir}")

    # 2. merge 실행
    print("\n" + "=" * 50)
    print("[PIPELINE] Step 2: merge (크롤 결과 + 프록시 결과 -> scan_targets 생성)")
    print("=" * 50)
    targets = merge(session_dir)

    output_path = session_dir / "scan_targets.json"
    save_json(str(output_path), targets)

    # 3. 결과 요약
    scannable = sum(1 for t in targets if t["can_scan"])
    skipped = len(targets) - scannable

    print("\n" + "=" * 50)
    print("[PIPELINE] 완료")
    print(f"  targets  : {len(targets)}")
    print(f"  can_scan : {scannable}")
    print(f"  skipped  : {skipped}")
    print(f"  결과 파일 : {output_path}")
    print("=" * 50)


if __name__ == "__main__":
    main()

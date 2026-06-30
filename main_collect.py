import json
import os
import sys
from datetime import datetime

from utilities.file_utils import load_json, save_json
from zap.client import ZapClient
from zap.importer import to_targets

_PROJECT_ROOT  = os.path.dirname(os.path.abspath(__file__))
_TARGET_CONFIG = os.path.join(_PROJECT_ROOT, "config", "target_config.json")


def main():
    target_cfg = load_json(_TARGET_CONFIG, default={})
    base_url = (target_cfg.get("target_url") or "").rstrip("/")
    if not base_url:
        print("[ERROR] target_config.json에 target_url이 없습니다.", file=sys.stderr)
        sys.exit(1)

    out_dir = os.path.join(_PROJECT_ROOT, "results", datetime.now().strftime("collection_%Y%m%d_%H%M%S"))
    os.makedirs(out_dir, exist_ok=True)

    print(f"[COLLECT] target: {base_url}")
    print("[COLLECT] ZAP 연결 중...")

    try:
        with ZapClient.from_config() as zap:
            print("[COLLECT] Spider 시작...")
            scan_id = zap.start_spider(base_url)
            zap.wait_spider(scan_id)
            messages = zap.get_all_messages(base_url=base_url)
    except Exception as e:
        print(f"[ERROR] ZAP API 연결 실패: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[COLLECT] ZAP 메시지 {len(messages)}건 수집")


    # RequestTarget 변환
    targets = to_targets(messages)
    print(f"\n[CONVERT] RequestTarget {len(targets)}건 (GET + query params 있는 것)")

    output = {
        "meta": {
            "target_base_url": base_url,
            "total_zap_messages": len(messages),
            "collected_targets": len(targets),
        },
        "targets": [t.to_dict() for t in targets],
    }
    targets_path = os.path.join(out_dir, "collected_targets.json")
    save_json(targets_path, output)
    print(f"[COLLECT] collected_targets.json -> {targets_path}")


if __name__ == "__main__":
    main()

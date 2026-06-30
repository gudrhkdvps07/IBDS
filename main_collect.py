import json
import os
import sys

from utilities.file_utils import load_json, save_json
from zap.client import ZapClient
from zap.importer import to_targets

_PROJECT_ROOT  = os.path.dirname(os.path.abspath(__file__))
_TARGET_CONFIG = os.path.join(_PROJECT_ROOT, "config", "target_config.json")
_OUT_DIR       = os.path.join(_PROJECT_ROOT, "results", "collection")
_SAMPLE_PATH   = os.path.join(_OUT_DIR, "raw_zap_messages_sample.json")
_TARGETS_PATH  = os.path.join(_OUT_DIR, "collected_targets.json")
_SAMPLE_COUNT  = 3


def main():
    target_cfg = load_json(_TARGET_CONFIG, default={})
    base_url = (target_cfg.get("target_url") or "").rstrip("/")
    if not base_url:
        print("[ERROR] target_config.json에 target_url이 없습니다.", file=sys.stderr)
        sys.exit(1)

    os.makedirs(_OUT_DIR, exist_ok=True)

    print(f"[COLLECT] target: {base_url}")
    print("[COLLECT] ZAP 연결 중...")

    try:
        with ZapClient.from_config() as zap:
            messages = zap.get_all_messages(base_url=base_url)
    except Exception as e:
        print(f"[ERROR] ZAP API 연결 실패: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[COLLECT] ZAP 메시지 {len(messages)}건 수집")

    # raw 샘플 저장 및 출력 (실제 필드명 확인용)
    sample = messages[:_SAMPLE_COUNT]
    save_json(_SAMPLE_PATH, sample)
    print(f"\n[SAMPLE] raw ZAP 메시지 {len(sample)}건 -> {_SAMPLE_PATH}")
    print(json.dumps(sample, ensure_ascii=False, indent=4))

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
    save_json(_TARGETS_PATH, output)
    print(f"[COLLECT] collected_targets.json -> {_TARGETS_PATH}")


if __name__ == "__main__":
    main()

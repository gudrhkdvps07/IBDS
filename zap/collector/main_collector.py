import os
import sys
from datetime import datetime
from pprint import pprint

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(os.path.dirname(_THIS_DIR))
sys.path.insert(0, _PROJECT_ROOT)  # utilities/ 등 프로젝트 루트 패키지 import용

from utilities.file_utils import load_json, save_json, normalize_base_url
from zap.collector.zap_collector import ZapCollector

_ZAP_CONFIG = os.path.join(_PROJECT_ROOT, "config", "zap_config.json")
_TARGET_CONFIG = os.path.join(_PROJECT_ROOT, "config", "target_config.json")
_DANGER_URL_FILE = os.path.join(_PROJECT_ROOT, "config", "spider_exclude.txt")

USE_AJAX_SPIDER = True  # 끄고 켜기는 여기서만, CLI 옵션 미사용


# 위험 URL 정규식 목록 로드 (빈 줄/주석 제외)
def _load_danger_patterns(path: str) -> list[str]:
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def main():
    target_cfg = load_json(_TARGET_CONFIG, default={})
    target_url = normalize_base_url(target_cfg.get("target_url", ""))
    if not target_url:
        print("[ERROR] target_config.json에 target_url이 없습니다.", file=sys.stderr)
        sys.exit(1)

    cookies = (target_cfg.get("auth") or {}).get("cookies", {})  # session 방식 auth만 지원
    danger_patterns = _load_danger_patterns(_DANGER_URL_FILE)

    out_dir = os.path.join(_PROJECT_ROOT, "results", datetime.now().strftime("collection_%Y%m%d_%H%M%S"))
    os.makedirs(out_dir, exist_ok=True)

    try:
        collector = ZapCollector.from_config(_ZAP_CONFIG)
        print(f"[ZAP] 버전: {collector.zap.core.version}")

        collector.new_session()
        collector.restrict_to_target_domain(target_url)
        collector.setup_context(target_url)
        collector.exclude_danger_urls(danger_patterns)  # Spider 실행 전 필수 등록

        if cookies:
            collector.set_session_cookie(cookies)
            print(f"[ZAP] 세션 쿠키 주입: {', '.join(cookies)}")

        collector.access_target(target_url)

        print(f"[COLLECT] Spider 시작: {target_url}")
        collector.run_spider(target_url)

        if USE_AJAX_SPIDER:
            print(f"[COLLECT] Ajax Spider 시작: {target_url}")
            collector.run_ajax_spider(target_url)

        if cookies:
            collector.clear_session_cookie()

        sample = collector.get_messages_sample(target_url, count=3)
        print("[ZAP] raw 메시지 샘플 (3건):")
        pprint(sample)
        sample_path = os.path.join(out_dir, "zap_raw_messages_sample.json")
        save_json(sample_path, sample)
        print(f"[ZAP] zap_raw_messages_sample.json -> {sample_path}")

        messages = collector.get_all_messages(target_url)
    except Exception as e:
        print(f"[ERROR] ZAP API 연결 실패: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[ZAP] 전체 메시지 {len(messages)}건 수집")
    messages_path = os.path.join(out_dir, "zap_messages.json")
    save_json(messages_path, messages)
    print(f"[ZAP] zap_messages.json -> {messages_path}")


if __name__ == "__main__":
    main()

import sys
import os
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from loader import load_cases
from http_executor import HttpExecutor
from response_store import HtmlResponseStore
from result_writer import ResultWriter
from core.session_context import latest_session_dir

_CASES_PATH = "tester/sample_test_cases.json"  # 입력 test case 파일 경로 (고정)


def main():
    try:
        cases = load_cases(_CASES_PATH)
    except (ValueError, OSError) as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)

    try:
        session_dir = latest_session_dir()
    except FileNotFoundError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)
    out_path = session_dir / "test_results.jsonl"
    store = HtmlResponseStore(Path("results/sessions/responses/html"))  # 실행 시작 시 responses/html/ 초기화

    print(f"Loaded {len(cases)} cases from {_CASES_PATH}")
    print(f"Output: {out_path}")

    counts = {"ok": 0, "err": 0, "skip": 0}  # 실행 결과 집계

    with ResultWriter(str(out_path)) as writer, HttpExecutor(response_store=store) as executor:
        for case in cases:
            result = executor.execute(case)
            writer.write(result)

            case_id = result.get("case_id", "?")
            if result.get("skipped"):
                counts["skip"] += 1
                print(f"[SKIP]  {case_id}: {result.get('skip_reason')}")
            elif result["response"] is not None:
                counts["ok"] += 1
                resp = result["response"]
                saved = "saved" if resp["body_saved"] else resp["body_save_reason"]
                print(f"[{resp['status_code']}]   {case_id}: {case.get('method')} {case.get('url')} ({saved})")
            else:
                counts["err"] += 1
                print(f"[ERR]   {case_id}: {result['error']}")

    print(f"\nDone — {counts['ok']} ok / {counts['err']} error / {counts['skip']} skipped")
    print(f"Results saved to {out_path}")


if __name__ == "__main__":
    main()

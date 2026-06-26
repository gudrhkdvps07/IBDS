import sys
from pathlib import Path

from loader import load_cases
from http_executor import HttpExecutor
from result_writer import ResultWriter

_CASES_PATH = "tester/sample_test_cases.json"


def _latest_session_dir() -> Path:
    sessions = sorted(Path("results/sessions").glob("session_*"))
    if not sessions:
        print("[ERROR] 세션 폴더가 없습니다. 크롤을 먼저 실행하세요.", file=sys.stderr)
        sys.exit(1)
    return sessions[-1]


def main():
    try:
        cases = load_cases(_CASES_PATH)
    except (ValueError, OSError) as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)

    out_path = _latest_session_dir() / "test_results.jsonl"
    print(f"Loaded {len(cases)} cases from {_CASES_PATH}")
    print(f"Output: {out_path}")

    counts = {"ok": 0, "err": 0, "skip": 0}

    with ResultWriter(str(out_path)) as writer, HttpExecutor() as executor:
        for case in cases:
            result = executor.execute(case)
            writer.write(result)

            case_id = result.get("case_id", "?")
            if result.get("skipped"):
                counts["skip"] += 1
                print(f"[SKIP]  {case_id}: {result.get('skip_reason')}")
            elif result["response"] is not None:
                counts["ok"] += 1
                print(f"[{result['response']['status_code']}]   {case_id}: {case.get('method')} {case.get('url')}")
            else:
                counts["err"] += 1
                print(f"[ERR]   {case_id}: {result['error']}")

    print(f"\nDone — {counts['ok']} ok / {counts['err']} error / {counts['skip']} skipped")
    print(f"Results saved to {out_path}")


if __name__ == "__main__":
    main()

import json
from pathlib import Path

from scanner.injector import load_targets, build_tasks
from scanner.executor import execute
from scanner.analyzer import analyze
from scanner.mutator import build_mutated_tasks

SESSION_DIR = Path("results/sessions/session_20260704_002432")
STRENGTH    = "MEDIUM"
TIMEOUT     = 10
MAX_WORKERS = 3

# 1. targets 로드
targets = load_targets(SESSION_DIR)
print(f"[1] targets={len(targets)}, can_scan={sum(1 for t in targets if t.get('can_scan'))}")

# 2. task 생성
tasks = build_tasks(targets, strength=STRENGTH, scan_xss=True, scan_sqli=True)
print(f"[2] tasks={len(tasks)}")

# 3. HTTP 전송
print(f"[3] 스캔 중... (max_workers={MAX_WORKERS}, timeout={TIMEOUT}s)")
results = execute(
    tasks,
    timeout=TIMEOUT,
    max_workers=MAX_WORKERS,
    output_file=str(SESSION_DIR / "scan_results.json"),
)
errors = sum(1 for r in results if r.get("error"))
print(f"[3] results={len(results)}, errors={errors}")

# 4. 분석
findings = analyze(results)
print(f"\n[4] findings={len(findings)}")
for f in findings:
    print(f"  [{f['confidence']}] {f['vuln_type']} {f['method']} | param={f['param']} | {f['evidence']}")

# 5. mutation (XSS hit 있으면)
mutated_tasks = build_mutated_tasks(findings, tasks)
if mutated_tasks:
    print(f"\n[5] mutated_tasks={len(mutated_tasks)} — WAF 우회 변형 재공격")
    m_results  = execute(mutated_tasks, timeout=TIMEOUT, max_workers=MAX_WORKERS)
    m_findings = analyze(m_results)
    print(f"    mutated findings={len(m_findings)}")
    for f in m_findings:
        print(f"  [{f['confidence']}] {f['vuln_type']} | param={f['param']} | {f['evidence']}")
    findings.extend(m_findings)
else:
    print("\n[5] mutation 대상 없음")

# 6. 결과 저장
out_path = SESSION_DIR / "findings.json"
with open(out_path, "w", encoding="utf-8") as fp:
    json.dump(findings, fp, ensure_ascii=False, indent=2)
print(f"\n결과 저장: {out_path}")

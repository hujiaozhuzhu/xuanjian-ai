from fp_sentinel.attack.v3_ai_pentest import AttackChainReasoner, PoCAutoGenerator, AutoVerifier, LabEnvironment
from fp_sentinel.attack.v3_ai_pentest.lab_environment import DEFAULT_TARGETS
from fp_sentinel.models import Finding, Severity

findings = [
    Finding(scanner="test", rule_id="py.xss.dom", severity=Severity.HIGH,
            file_path="app.py", line_start=10, code_snippet="v = request.args"),
    Finding(scanner="test", rule_id="py.injection.sql", severity=Severity.CRITICAL,
            file_path="app.py", line_start=20, code_snippet="q = SELECT || uid"),
    Finding(scanner="test", rule_id="py.injection.command", severity=Severity.HIGH,
            file_path="app.py", line_start=30, code_snippet="os.system(cmd)"),
]

reasoner = AttackChainReasoner(attention_heads=4)
report = reasoner.reason(findings, project="demo")
print(f"Chains: {len(report.chains)}, Isolated: {len(report.isolated_findings)}")

if report.chains:
    chain = report.chains[0]
    print(f"Top chain risk: {chain.overall_risk}, prob: {chain.chain_probability}%")

generator = PoCAutoGenerator()
if report.chains:
    poc_result = generator.generate_for_chain(report.chains[0])
    print(f"PoC scripts: {len(poc_result.scripts)}, plan steps: {len(poc_result.verification_plan)}")

from fp_sentinel.attack.v3_ai_pentest.attack_chain_reasoner import to_mermaid, to_ascii, to_json_graph
print(f"Mermaid: {len(to_mermaid(report))} chars, ASCII: {len(to_ascii(report))} chars")

verifier = AutoVerifier(allow_docker=False)
session = verifier.verify_findings(findings)
print(f"Verification: total={session.total_findings}, sim={session.simulated_count}")

lab = LabEnvironment()
print(f"Lab backend: {lab.backend.value}, degraded: {lab.is_degraded}")
if "python-vuln-app" in DEFAULT_TARGETS:
    target = lab.start_target(DEFAULT_TARGETS["python-vuln-app"])
    print(f"Lab target: {target.name}, port: {target.host_port}, status: {target.status.value}")
    lab.stop_all()
print("ALL TESTS PASSED")

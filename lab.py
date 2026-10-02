"""
Master Research Lab CLI Interface
Unified controller for the AI Security Detection & Internal Pentest Lab.
"""

import sys
import argparse
from pathlib import Path

# Add root directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from experiments.runner import ExperimentRunner
from experiments.matrix_generator import DetectionMatrixGenerator
from experiments.telemetry_failure import TelemetryFailureExperiment
from experiments.report_generator import ResearchReportGenerator
from backend.server import start_backend_server as start_server
from core.config import DATA_DIR, EXPERIMENTS_DIR, LOGS_DIR

def cmd_run(args):
    runner = ExperimentRunner()
    if args.scenario.lower() == "all":
        runner.run_all()
    else:
        runner.run_scenario(args.scenario)

def cmd_experiment(args):
    runner = ExperimentRunner()
    failure_exp = TelemetryFailureExperiment(runner)
    metrics = failure_exp.execute_experiment()
    print("\n" + "="*70)
    print(" EMPIRICAL TELEMETRY FAILURE & DETECTION METRICS")
    print("="*70)
    print(f" Normal Telemetry Coverage:  {metrics['telemetry_coverage_normal_pct']}%")
    print(f" Gap Telemetry Coverage:     {metrics['telemetry_coverage_gap_pct']}%")
    print(f" Telemetry Loss during Gap:  {metrics['telemetry_loss_pct']}%")
    print(f" Detection Normal Coverage:  {metrics['detection_coverage_normal_pct']}%")
    print(f" Detection Gap Coverage:     {metrics['detection_coverage_gap_pct']}%")
    print(f" Measured False Pos. Rate:   {metrics['false_positive_rate_pct']}%")
    print(f" Mean Detection Delay:       {metrics['simulated_detection_delay_ms']} ms")
    print("\nKey Observations:")
    for obs in metrics["observations"]:
        print(f" - {obs}")
    print(f"\n[NOTE] {metrics['disclaimer']}")

def cmd_matrix(args):
    runner = ExperimentRunner()
    matrix_gen = DetectionMatrixGenerator(runner)
    print("\n" + matrix_gen.render_markdown_table() + "\n")

def cmd_report(args):
    runner = ExperimentRunner()
    report_gen = ResearchReportGenerator(runner)
    report_gen.generate_report(args.output)

def cmd_baseline(args):
    from core.baseline import BaselineEngine
    b = BaselineEngine()
    res = b.establish_normal_baseline()
    print("\n" + "="*70)
    print(" ESTABLISHED PRE-ATTACK NORMAL BASELINE PROFILE")
    print("="*70)
    print(f" Sample Events Recorded: {res['total_sample_events']}")
    print(f" Users Profiled:         {', '.join(res['users_profiled'])}")
    print(f" Hosts Profiled:         {', '.join(res['hosts_profiled'])}")
    print("\nBaseline Metrics Table:")
    for item in res["baseline_table"]:
        print(f" - {item['metric']:<28} | {item['baseline_value']}")
    print("\n[+] Normal baseline saved to /data/baselines/baseline_established.json")

def cmd_dashboard(args):
    import os
    port = getattr(args, "port", int(os.environ.get("PORT", 8080)))
    host = getattr(args, "host", os.environ.get("HOST", "0.0.0.0" if os.environ.get("PORT") else "127.0.0.1"))
    start_server(port=port, host=host)

def cmd_reset(args):
    print("[*] Resetting lab state and cleaning /data/ logs and experiments...")
    for f in EXPERIMENTS_DIR.glob("*.json"):
        try:
            f.unlink()
        except Exception:
            pass
    for f in LOGS_DIR.glob("*.json"):
        try:
            f.unlink()
        except Exception:
            pass
    from core.baseline import BaselineEngine
    BaselineEngine().establish_normal_baseline()
    print("[+] All previous experiment sessions and logs have been wiped cleanly. Normal baseline re-established.")

def main():
    import os
    parser = argparse.ArgumentParser(
        description="AI Security Detection & Internal Pentest Research Lab CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Command: run
    p_run = subparsers.add_parser("run", help="Run safe attack scenario simulations")
    p_run.add_argument("scenario", choices=["1", "2", "3", "4", "5", "6", "7", "all"], default="all", nargs="?", help="Scenario number or 'all'")
    p_run.set_defaults(func=cmd_run)

    # Command: baseline
    p_base = subparsers.add_parser("baseline", help="Establish normal pre-attack baseline profile")
    p_base.set_defaults(func=cmd_baseline)

    # Command: experiment
    p_exp = subparsers.add_parser("experiment", help="Run dedicated telemetry failure experiment")
    p_exp.set_defaults(func=cmd_experiment)

    # Command: matrix
    p_mat = subparsers.add_parser("matrix", help="Display detection coverage matrix")
    p_mat.set_defaults(func=cmd_matrix)

    # Command: report
    p_rep = subparsers.add_parser("report", help="Generate academic Markdown research report")
    p_rep.add_argument("-o", "--output", help="Optional custom output path")
    p_rep.set_defaults(func=cmd_report)

    # Command: dashboard
    p_dash = subparsers.add_parser("dashboard", help="Start web dashboard & investigation API")
    p_dash.add_argument("-p", "--port", type=int, default=int(os.environ.get("PORT", 8080)), help="Web server port (default: 8080 or $PORT)")
    p_dash.add_argument("--host", type=str, default=os.environ.get("HOST", "0.0.0.0" if os.environ.get("PORT") else "127.0.0.1"), help="Host IP address")
    p_dash.set_defaults(func=cmd_dashboard)

    # Command: reset
    p_reset = subparsers.add_parser("reset", help="Reset all experiment data and logs")
    p_reset.set_defaults(func=cmd_reset)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)

if __name__ == "__main__":
    main()

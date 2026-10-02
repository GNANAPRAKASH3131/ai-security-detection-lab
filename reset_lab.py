"""
Lab Reset and State Cleanup Script
"""

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
EXPERIMENTS_DIR = BASE_DIR / "data" / "experiments"
LOGS_DIR = BASE_DIR / "data" / "logs"

def reset_lab():
    print("[*] Performing safe lab reset...")
    exp_count = 0
    for f in EXPERIMENTS_DIR.glob("*.json"):
        f.unlink()
        exp_count += 1
    
    log_count = 0
    for f in LOGS_DIR.glob("*.json"):
        f.unlink()
        log_count += 1

    print(f"[+] Cleaned {exp_count} experiment records and {log_count} SIEM session logs.")
    print("[+] Lab state is restored to pristine baseline.")

if __name__ == "__main__":
    reset_lab()

import subprocess
import glob
import os
from datetime import datetime

TARGET = "192.168.194.132"
SCAN_DIR = "/home/boujenan/security-monitor/scans"
LOG_DIR = "/home/boujenan/security-monitor/logs"


def run_scan():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"{SCAN_DIR}/scan_{timestamp}.xml"

    command = [
        "sudo",
        "nmap",
        "-sV",
        "-O",
        "-oX",
        output_file,
        TARGET
    ]

    print("=== 1. Lancement du scan Nmap ===")
    print(f"Cible : {TARGET}")

    result = subprocess.run(command)

    if result.returncode != 0:
        print("❌ Échec du scan Nmap.")
        return None

    print("✅ Scan terminé.")
    print(f"Résultat : {output_file}")

    return output_file


def get_previous_scan(current_scan):
    scans = glob.glob(f"{SCAN_DIR}/scan_*.xml")

    scans = [
        scan for scan in scans
        if os.path.abspath(scan) != os.path.abspath(current_scan)
    ]

    if not scans:
        return None

    return max(scans, key=os.path.getmtime)


def compare_scans(baseline, current):
    print("\n=== 2. Comparaison ===")

    command = [
        "python3",
        "/home/boujenan/security-monitor/scripts/compare_scans.py",
        baseline,
        current
    ]

    subprocess.run(command)


def write_log(current_scan, previous_scan):
    os.makedirs(LOG_DIR, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_file = f"{LOG_DIR}/monitor.log"

    with open(log_file, "a") as file:
        file.write(
            f"[{timestamp}] Scan : {current_scan} | "
            f"Comparé avec : {previous_scan}\n"
        )

    print("\n=== 3. Journalisation ===")
    print(f"✅ Résultat enregistré dans : {log_file}")


def main():
    current_scan = run_scan()

    if current_scan is None:
        return

    previous_scan = get_previous_scan(current_scan)

    if previous_scan is None:
        print("\nℹ️ Aucun scan précédent disponible.")
        return

    print(f"\nScan précédent : {previous_scan}")

    compare_scans(previous_scan, current_scan)

    write_log(current_scan, previous_scan)


if __name__ == "__main__":
    main()

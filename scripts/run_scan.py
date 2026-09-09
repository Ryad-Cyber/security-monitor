import subprocess
from datetime import datetime

TARGET = "192.168.194.132"
SCAN_DIR = "/home/boujenan/security-monitor/scans"


def run_nmap_scan():
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

    print("=== Lancement du scan Nmap ===")
    print(f"Cible : {TARGET}")
    print(f"Fichier : {output_file}")

    result = subprocess.run(command)

    if result.returncode == 0:
        print("\n✅ Scan terminé avec succès.")
        print(f"Résultat enregistré dans : {output_file}")
    else:
        print("\n❌ Le scan Nmap a échoué.")


if __name__ == "__main__":
    run_nmap_scan()

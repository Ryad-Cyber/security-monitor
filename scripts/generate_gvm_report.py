import re
import xml.etree.ElementTree as ET
from collections import Counter

INPUT = "reports/gvm_report.xml"
OUTPUT = "reports/gvm_report.md"


def text(element, path, default=""):
    node = element.find(path)
    if node is None or node.text is None:
        return default
    return " ".join(node.text.split())


tree = ET.parse(INPUT)
root = tree.getroot()
report = root.find("report")

if report is None:
    raise SystemExit("Structure XML GVM invalide.")

task = text(root.find("report"), "task/name", "Inconnue")
creation = text(root, "creation_time", "Inconnue")
status = text(report, "scan_run_status", "Inconnu")

hosts = text(report, "hosts/count", "0")
ports = text(report, "ports/count", "0")
apps = text(report, "apps/count", "0")
cves = text(report, "cves/count", "0")
vulns_total = text(report, "vulns/count", "0")

results = report.findall("results/result")

levels = Counter()
vulnerabilities = []

for result in results:
    name = text(result, "name", "Sans nom")
    host = text(result, "host", "Inconnu")
    port = text(result, "port", "Inconnu")
    threat = text(result, "threat", "Unknown")

    try:
        severity = float(text(result, "severity", "0"))
    except ValueError:
        severity = 0.0

    description = text(result, "description", "")
    solution = text(result, "solution", "")

    cve_text = " ".join([name, description, solution])
    cves_found = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", cve_text)))

    levels[threat] += 1

    vulnerabilities.append({
        "name": name,
        "host": host,
        "port": port,
        "threat": threat,
        "severity": severity,
        "cves": cves_found,
        "solution": solution,
    })

vulnerabilities.sort(key=lambda x: x["severity"], reverse=True)

with open(OUTPUT, "w", encoding="utf-8") as f:
    f.write("# Rapport automatique GVM/OpenVAS\n\n")

    f.write("## Informations générales\n\n")
    f.write(f"- **Tâche :** {task}\n")
    f.write(f"- **Date :** {creation}\n")
    f.write(f"- **Statut :** {status}\n\n")

    f.write("## Synthèse\n\n")
    f.write(f"- **Hôtes analysés :** {hosts}\n")
    f.write(f"- **Ports identifiés :** {ports}\n")
    f.write(f"- **Applications identifiées :** {apps}\n")
    f.write(f"- **CVE identifiées :** {cves}\n")
    f.write(f"- **Vulnérabilités GVM :** {vulns_total}\n")
    f.write(f"- **Résultats détaillés dans le XML :** {len(results)}\n\n")

    f.write("## Répartition par niveau\n\n")
    f.write("| Niveau | Nombre |\n")
    f.write("|---|---:|\n")

    for level in ["Critical", "High", "Medium", "Low", "Log", "Unknown"]:
        if levels[level]:
            f.write(f"| {level} | {levels[level]} |\n")

    f.write("\n## Principales vulnérabilités\n\n")
    f.write("| Niveau | CVSS | Vulnérabilité | Hôte | Port |\n")
    f.write("|---|---:|---|---|---|\n")

    for v in vulnerabilities[:20]:
        name = v["name"].replace("|", "\\|")
        f.write(
            f"| {v['threat']} | {v['severity']:.1f} | "
            f"{name} | {v['host']} | {v['port']} |\n"
        )

    f.write("\n## Détails\n\n")

    for i, v in enumerate(vulnerabilities, 1):
        f.write(f"### {i}. {v['name']}\n\n")
        f.write(f"- **Niveau :** {v['threat']}\n")
        f.write(f"- **CVSS :** {v['severity']:.1f}\n")
        f.write(f"- **Hôte :** {v['host']}\n")
        f.write(f"- **Port :** {v['port']}\n")

        if v["cves"]:
            f.write(f"- **CVE :** {', '.join(v['cves'])}\n")

        if v["solution"]:
            f.write(f"- **Solution :** {v['solution']}\n")

        f.write("\n")

print(f"Rapport généré : {OUTPUT}")
print(f"Résultats traités : {len(results)}")

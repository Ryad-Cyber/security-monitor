# Security Monitor — Surveillance et automatisation de la sécurité

Solution de surveillance de la sécurité combinant des scans Nmap périodiques, une analyse de vulnérabilités GVM/OpenVAS et un système d'alerte automatisé (email et iLert). Projet réalisé dans le cadre d'un stage en cybersécurité.

## Fonctionnalités

- **Scans Nmap automatisés** toutes les 5 minutes (Cron) sur une cible définie
- **Détection des changements** de ports ouverts entre deux scans (surveillance de la surface d'exposition)
- **Alertes automatiques** en cas de changement détecté :
  - email via SMTP
  - incident iLert via API (priorité HIGH)
- **Analyse de vulnérabilités** avec Greenbone Community Edition (GVM/OpenVAS) déployé sous Docker
- **Génération de rapports** Markdown à partir des exports XML de GVM
- **CI/CD** avec GitHub Actions : vérification de la syntaxe Python à chaque push et packaging du projet en artefact

## Architecture

| Script | Rôle |
|---|---|
| `monitor.py` | Orchestrateur : lance le scan, compare, déclenche les alertes |
| `run_scan.py` | Exécute le scan Nmap et enregistre le résultat |
| `parse_nmap.py` | Analyse la sortie Nmap (ports, services) |
| `compare_scans.py` | Compare deux scans et détecte les ports ouverts ou fermés |
| `alert.py` | Envoie les alertes (SMTP et API iLert) |
| `generate_gvm_report.py` | Convertit un export XML GVM en rapport Markdown |

## Environnement de test

- Machine de supervision : Ubuntu (VMware Workstation)
- Cible : Metasploitable 2 (machine volontairement vulnérable)
- GVM/OpenVAS : Greenbone Community Edition sous Docker (gvmd, PostgreSQL, OpenVAS, GSAD)

## Résultats

- Scan complet GVM de Metasploitable 2 : **68 vulnérabilités détectées** (Critical, High, Medium, Low), **122 CVE** associées, sévérité maximale **Critical (CVSS 10.0)**
- Alerte testée et validée : l'ouverture d'un nouveau port (9999) sur la cible déclenche l'envoi de l'email et la création d'un incident iLert

## Configuration

Les identifiants ne sont jamais stockés dans le code. Ils sont lus depuis un fichier `.env` (non versionné) :

Un modèle est fourni dans `.env.example`.

## Limites et pistes d'amélioration

- L'export XML de GVM est encore manuel : il pourrait être automatisé via l'API GMP
- Pas encore d'alerte déclenchée selon la sévérité des vulnérabilités OpenVAS (uniquement sur changement de ports Nmap)
- Ajout possible d'un tableau de bord ou d'une intégration SIEM (Elastic, Wazuh)

---

**Auteur** : Ryad Boujenan

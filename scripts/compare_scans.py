from alert import send_email_alert, send_ilert_alert
import sys
import xml.etree.ElementTree as ET


def get_open_ports(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    ports = {}

    for host in root.findall("host"):
        host_ports = host.find("ports")

        if host_ports is None:
            continue

        for port in host_ports.findall("port"):
            state = port.find("state")

            if state is None or state.get("state") != "open":
                continue

            port_number = port.get("portid")
            protocol = port.get("protocol")
            port_id = f"{port_number}/{protocol}"

            service = port.find("service")

            if service is not None:
                service_name = service.get("name", "unknown")
                product = service.get("product", "")
                version = service.get("version", "")
            else:
                service_name = "unknown"
                product = ""
                version = ""

            ports[port_id] = {
                "name": service_name,
                "product": product,
                "version": version
            }

    return ports


def compare_scans(baseline_file, current_file):

    baseline = get_open_ports(baseline_file)
    current = get_open_ports(current_file)

    baseline_ports = set(baseline.keys())
    current_ports = set(current.keys())

    new_ports = current_ports - baseline_ports
    closed_ports = baseline_ports - current_ports

    print("=== Comparaison des scans ===")
import sys
import xml.etree.ElementTree as ET
from alert import send_email_alert


def get_open_ports(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    ports = {}

    for host in root.findall("host"):
        host_ports = host.find("ports")

        if host_ports is None:
            continue

        for port in host_ports.findall("port"):
            state = port.find("state")

            if state is None or state.get("state") != "open":
                continue

            port_number = port.get("portid")
            protocol = port.get("protocol")
            port_id = f"{port_number}/{protocol}"

            service = port.find("service")

            if service is not None:
                service_name = service.get("name", "unknown")
                product = service.get("product", "")
                version = service.get("version", "")
            else:
                service_name = "unknown"
                product = ""
                version = ""

            ports[port_id] = {
                "name": service_name,
                "product": product,
                "version": version
            }

    return ports


def compare_scans(baseline_file, current_file):

    baseline = get_open_ports(baseline_file)
    current = get_open_ports(current_file)

    baseline_ports = set(baseline.keys())
    current_ports = set(current.keys())

    new_ports = current_ports - baseline_ports
    closed_ports = baseline_ports - current_ports

    print("=== Comparaison des scans ===")
    print(f"Baseline : {baseline_file}")
    print(f"Scan actuel : {current_file}")
    print(f"Ports ouverts dans le baseline : {len(baseline_ports)}")
    print(f"Ports ouverts dans le scan actuel : {len(current_ports)}")

    if new_ports:
        print("\n⚠️ Nouveaux ports détectés :")

        message = "🚨 Nouveau port ouvert détecté sur 192.168.194.132 :\n\n"

        for port in sorted(new_ports):
            service = current[port]

            label = service["product"] or service["name"]

            if service["version"]:
                label += f" {service['version']}"

            print(f"  + {port} - {label}")

            message += f"+ {port} - {label}\n"

        send_email_alert(
            "🚨 Alerte sécurité - Nouveau port détecté",
            message
        )

        send_ilert_alert(
            "🚨 Nouveau port détecté sur 192.168.194.132"
        )

    else:
        print("\nAucun nouveau port détecté.")

    if closed_ports:
        print("\n⚠️ Ports fermés détectés :")

        for port in sorted(closed_ports):
            print(f"  - {port}")

    else:
        print("\nAucun port fermé détecté.")

    print("\n=== Fin de la comparaison ===")


if __name__ == "__main__":

    if len(sys.argv) != 3:
        print("Usage : python3 compare_scans.py <baseline> <current>")
        sys.exit(1)

    compare_scans(sys.argv[1], sys.argv[2])

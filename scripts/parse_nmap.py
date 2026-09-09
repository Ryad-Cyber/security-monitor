import xml.etree.ElementTree as ET

XML_FILE = "/home/boujenan/security-monitor/scans/scan_initial.xml"


def parse_nmap_scan(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    for host in root.findall("host"):
        address = host.find("address")
        if address is not None:
            ip = address.get("addr")
            print(f"\nCible : {ip}")

        ports = host.find("ports")

        if ports is None:
            continue

        for port in ports.findall("port"):
            state = port.find("state")

            if state is None or state.get("state") != "open":
                continue

            port_number = port.get("portid")
            protocol = port.get("protocol")

            service = port.find("service")

            if service is not None:
                service_name = service.get("name", "unknown")
                version = service.get("version", "")
                product = service.get("product", "")

                service_info = product
                if version:
                    service_info += f" {version}"

                if not service_info:
                    service_info = service_name
            else:
                service_info = "unknown"

            print(
                f"{port_number}/{protocol} - {service_info}"
            )


if __name__ == "__main__":
    parse_nmap_scan(XML_FILE)

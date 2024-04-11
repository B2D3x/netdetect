from scapy.all import *
import ipaddress

DEFAULT_LIST_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

ANCHO_PORT = 10
ANCHO_STATUS = 10
ANCHO_SERVICE = 60
MARGEN_SERVICE = 4

TITLE_ASCI = r""" __   __     ______     ______   _____     ______     ______   ______     ______     ______  
/\ "-.\ \   /\  ___\   /\__  _\ /\  __-.  /\  ___\   /\__  _\ /\  ___\   /\  ___\   /\__  _\ 
\ \ \-.  \  \ \  __\   \/_/\ \/ \ \ \/\ \ \ \  __\   \/_/\ \/ \ \  __\   \ \ \____  \/_/\ \/ 
 \ \_\\"\_\  \ \_____\    \ \_\  \ \____-  \ \_____\    \ \_\  \ \_____\  \ \_____\    \ \_\ 
  \/_/ \/_/   \/_____/     \/_/   \/____/   \/_____/     \/_/   \/_____/   \/_____/     \/_/
  """

# Check that the network is in the correct format
def validate_network(network):
    try:
        network_check = ipaddress.IPv4Network(network, strict=False)
        return True
    except ValueError:
        print(f"The {network} does not have the correct format.")
        return False

# Scans the network returning the ip of the devices that have responded to the packet.
def arp_scan(network):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network), timeout=4, verbose=False)
    return [rcv.sprintf("%ARP.psrc%") for snd, rcv in ans]

# Check that it can receive TCP packets, trying it through different ports.
def tcp_ping(target_host, ports):
    for port in ports:
        src_port = RandShort()
        response = sr1(IP(dst=target_host)/TCP(sport=src_port, dport=port, flags="S"), timeout=4, verbose=False)
        if response and response.haslayer(TCP):
            if response[TCP].flags == 18:
                return True
    return False

# Check that it can receive UDP packets, trying it through different ports.
def udp_ping(target_host, ports):
    for port in ports:
        src_port = RandShort()
        response = sr1(IP(dst=target_host)/UDP(sport=src_port, dport=port), timeout=4, verbose=False)
        if response and response.haslayer(UDP):
            return True
    return False

# Checks that it can receive ICMP packets
def icmp_ping(target_host):
    response = sr1(IP(dst=target_host)/ICMP(), timeout=4, verbose=False)
    if response and response.haslayer(ICMP):
        return True
    return False

# Scans the target, checking if the port is open.
def tcp_scan(target_host, ports):
    open_ports = {}
    version_service = ""
    version_server = ""
    for port in ports:
        src_port = RandShort()
        response = sr1(IP(dst=target_host)/TCP(sport=src_port, dport=port, flags="S"), timeout=4, verbose=False)
        # 
        if response and response.haslayer(TCP):
            if response[TCP].flags == 0x12:  
                version_service, version_server = get_service_server_name(target_host, port)
                open_ports[port] = version_service + " " + version_server
            
    return open_ports

# Scans the target, checking if the port is filtered.
def ack_scan(target_host, ports):
    filtered_ports = []

    for port in ports:
        response = sr1(IP(dst=target_host)/TCP(dport=port, flags="A"), timeout=4, verbose=False)

        if not response:
            filtered_ports.append(port)

    return filtered_ports

# Gets the service version and server if available
def get_service_server_name(target_host, port):
    version_service = ""
    server_version = ""

    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.settimeout(1)

    try:
        tcp_socket.connect((target_host, port))
        tcp_socket.send(b"GET / HTTP/1.0\r\n\r\n")
        banner = tcp_socket.recv(1024).decode()

        banner_lines = banner.split("\n")
        if len(banner_lines) > 0:
            version_line = banner_lines[0]
            version_parts = version_line.split(" ")
            if len(version_parts) > 1:
                version_service = version_parts[0]

            headers = banner.split("\r\n\r\n")[0].split("\r\n")[1:]
            for header in headers:
                if header.startswith("Server:"):
                    server_version = header.split(":")[1].strip()
                    break

    except Exception as e:
        e = e
    finally:
        tcp_socket.close()

    return version_service, server_version

# Obtains the operating system, if possible
def get_version_system_operative (target_host):
    system_operative = "Unable to detect Operating System"

    response = sr1(IP(dst=target_host)/ICMP(), timeout=4, verbose=False)
    if response and response.haslayer(IP):
        ttl = response[IP].ttl
        system_operative = "Linux"

        if ttl > 64:
            system_operative = "Windows"
        elif ttl >= 255:
            system_operative = "FreeBSD"
    else:
        response = sr1(IP(dst=target_host)/TCP(dport=port, flags="S"), timeout=4, verbose=False)

        if response and response.haslayer(TCP):
            if response[TCP].flags == 0x12:
                system_operative = "Linux"
            elif response[TCP].flags == 0x14:
                system_operative = "Windows"
    
    return system_operative

def output_info_host (open_ports, filter_ports):
    for port, service in open_ports.items():
        port_formatted = f"{port}".center(ANCHO_PORT)
        status_formatted = "open".center(ANCHO_STATUS)
        service_formatted = f"{service}".center(ANCHO_SERVICE)
        print(f"| {port_formatted} | {status_formatted} | {service_formatted} |")

    for port in filter_ports:
        port_formatted = f"{port}".center(ANCHO_PORT)
        status_formatted = "filtered".center(ANCHO_STATUS)
        service_formatted = ''.center(ANCHO_SERVICE)  # Servicio vacío para los puertos filtrados
        print(f"| {port_formatted} | {status_formatted} | {service_formatted} |")

def output_info_ping(host, comunication, status):
    icon_status = "✕"
    if status: icon_status = "✓"
    print(f"Host {host} receives {comunication} communication: [{icon_status}] ")

# Allows entry of the network to be scanned
def input_network ():
    network = ""
    print("")
    try:
        network = input("Enter a network (Example: 192.168.1.100/24): ")

        if not validate_network(network):
            input_network()

        return network
    except KeyboardInterrupt:
        print("\n")
        print("The operation has been cancelled")
        exit()

def main() :
    print(TITLE_ASCI)

    network = input_network()

    print("[~] Scanning the network for available hosts")

    hosts = arp_scan(network)

    hosts.append(network.split("/")[0])
    hosts = set(hosts)

    print("[+] Hosts available :", hosts)


    for host in hosts:
        tcp_status = tcp_ping(host, DEFAULT_LIST_PORTS)
        udp_status = udp_ping(host, DEFAULT_LIST_PORTS)
        icmp_status = icmp_ping(host)

        print("\n")
        output_info_ping(host, "TCP", tcp_status)
        output_info_ping(host, "UDP", udp_status)
        output_info_ping(host, "ICMP", icmp_status)

        print("\n[~] Scanning host :", host)
        os_host = get_version_system_operative(host)
        print("     OS: " + os_host)
        print("\n")


        open_ports = None
        if tcp_status:
            open_ports = tcp_scan(host, DEFAULT_LIST_PORTS)
        
        filter_ports = ack_scan(host, DEFAULT_LIST_PORTS)

        if open_ports != None and filter_ports.count() > 0:
            print(f"| {'Port'.center(ANCHO_PORT)} | {'Status'.center(ANCHO_STATUS)} | {'Service'.center(ANCHO_SERVICE)} |")
            output_info_host(open_ports, filter_ports)



if __name__ == "__main__":
    main()
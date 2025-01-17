from scapy.all import ARP, Ether, srp, conf

def scan_vlan(vlan_ip_range):
    # Configurăm conf pentru a evita problemele de permisiune
    conf.verb = 0
    
    # Creăm un pachet ARP
    arp_request = ARP(pdst=vlan_ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp_request
    
    # Trimitem pachetul și primim răspunsurile
    result = srp(packet, timeout=2, verbose=0)[0]

    active_ips = []
    
    # Extragem IP-urile active
    for sent, received in result:
        active_ips.append(received.psrc)

    return active_ips

if __name__ == "__main__":
    # Specifică intervalul de IP-uri al VLAN-ului tău
    vlan_ip_range = "192.168.1.0/24"  # Schimbă cu intervalul tău
    active_ips = scan_vlan(vlan_ip_range)

    print("Mașinile active din VLAN:")
    for ip in active_ips:
        print(ip)

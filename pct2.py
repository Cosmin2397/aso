from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient
import sys
import socket
import concurrent.futures
import ipaddress

def get_azure_clients(subscription_id):
    """Inițializează clienții Azure necesari."""
    credential = DefaultAzureCredential()
    network_client = NetworkManagementClient(credential, subscription_id)
    compute_client = ComputeManagementClient(credential, subscription_id)
    return network_client, compute_client

def get_vnet_subnet_info(network_client, resource_group, vnet_name, subnet_name):
    """Obține informații despre subnet-ul specificat."""
    subnet = network_client.subnets.get(
        resource_group,
        vnet_name,
        subnet_name
    )
    return subnet.address_prefix

def check_ip_active(ip):
    """Verifică dacă un IP este activ folosind o conexiune socket."""
    try:
        socket.create_connection((ip, 80), timeout=1)
        return ip
    except (socket.timeout, socket.error):
        try:
            socket.create_connection((ip, 443), timeout=1)
            return ip
        except (socket.timeout, socket.error):
            return None

def scan_network(subnet_cidr):
    """Scanează toate IP-urile din subnet pentru a găsi mașini active."""
    network = ipaddress.IPv4Network(subnet_cidr)
    active_ips = []
    
    # Folosim ThreadPoolExecutor pentru scanare paralelă
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_ip = {executor.submit(check_ip_active, str(ip)): ip 
                       for ip in network.hosts()}
        
        for future in concurrent.futures.as_completed(future_to_ip):
            result = future.result()
            if result:
                active_ips.append(result)
    
    return active_ips

def main():
    # Parametrii necesari
    subscription_id = input("Introduceți ID-ul subscripției Azure: ")
    resource_group = input("Introduceți numele Resource Group: ")
    vnet_name = input("Introduceți numele Virtual Network: ")
    subnet_name = input("Introduceți numele Subnet: ")
    
    try:
        # Inițializare clienți Azure
        network_client, compute_client = get_azure_clients(subscription_id)
        
        # Obține informații despre subnet
        subnet_cidr = get_vnet_subnet_info(network_client, resource_group, 
                                         vnet_name, subnet_name)
        
        print(f"\nScanare subnet: {subnet_cidr}")
        print("Scanare în progres...")
        
        # Scanează rețeaua pentru IP-uri active
        active_ips = scan_network(subnet_cidr)
        
        # Afișează rezultatele
        print("\nMașini active găsite:")
        for ip in sorted(active_ips, key=lambda ip: [int(part) for part in ip.split('.')]):
            print(f"IP activ: {ip}")
        
        print(f"\nTotal mașini active găsite: {len(active_ips)}")
        
    except Exception as e:
        print(f"Eroare: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
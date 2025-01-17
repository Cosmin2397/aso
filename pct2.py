import socket
import ipaddress
import concurrent.futures
from datetime import datetime
import platform
import subprocess

def get_my_ip():
    """Obține adresa IP a mașinii locale."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Nu trebuie să fie o conexiune reală
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def ping(ip):
    """Verifică dacă un IP răspunde la ping."""
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', str(ip)]
    try:
        output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1)
        return output.returncode == 0
    except subprocess.TimeoutExpired:
        return False

def check_ports(ip):
    """Verifică dacă porturile comune sunt deschise."""
    common_ports = [80, 443, 22, 3389]  # HTTP, HTTPS, SSH, RDP
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((str(ip), port))
            if result == 0:
                return True
            sock.close()
        except:
            continue
    return False

def scan_ip(ip):
    """Scanează un IP pentru a verifica dacă este activ."""
    if ping(ip) or check_ports(ip):
        try:
            hostname = socket.gethostbyaddr(str(ip))[0]
        except socket.herror:
            hostname = "N/A"
        return (str(ip), hostname)
    return None

def scan_network(network_cidr):
    """Scanează toate IP-urile din rețea."""
    print(f"Începere scanare pentru rețeaua: {network_cidr}")
    start_time = datetime.now()
    
    # Convertește CIDR în obiect de rețea
    network = ipaddress.IPv4Network(network_cidr)
    active_hosts = []
    
    # Folosește ThreadPoolExecutor pentru scanare paralelă
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_ip = {executor.submit(scan_ip, ip): ip for ip in network.hosts()}
        
        total_ips = len(future_to_ip)
        completed = 0
        
        for future in concurrent.futures.as_completed(future_to_ip):
            completed += 1
            if completed % 10 == 0:
                print(f"Progres: {completed}/{total_ips} IP-uri scanate")
            
            result = future.result()
            if result:
                active_hosts.append(result)
    
    end_time = datetime.now()
    duration = end_time - start_time
    
    return active_hosts, duration

def main():
    # Obține IP-ul local și determină rețeaua
    my_ip = get_my_ip()
    network = ipaddress.IPv4Interface(f"{my_ip}/24").network
    print(f"IP local detectat: {my_ip}")
    print(f"Scanare rețea: {network}")
    
    # Efectuează scanarea
    active_hosts, duration = scan_network(str(network))
    
    # Afișează rezultatele
    print("\nRezultatele scanării:")
    print("-" * 50)
    print(f"{'IP':<15} | {'Hostname':<35}")
    print("-" * 50)
    
    for ip, hostname in sorted(active_hosts, key=lambda x: ipaddress.IPv4Address(x[0])):
        print(f"{ip:<15} | {hostname:<35}")
    
    print("-" * 50)
    print(f"\nScanare completă!")
    print(f"Timp total: {duration}")
    print(f"Host-uri active găsite: {len(active_hosts)}")

if __name__ == "__main__":
    main()
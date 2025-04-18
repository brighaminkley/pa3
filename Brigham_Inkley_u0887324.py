#!/usr/bin/env python3

import os
import sys
import subprocess
import argparse

try:
    import docker
except ImportError:
    docker = None

# Configuration files
DAEMONS_CONFIG = """zebra=yes
bgpd=no
ospfd=yes
"""

FRR_CONF = """!
hostname frr
password zebra
log stdout
!
router ospf
 network 10.0.0.0/8 area 0
!
"""

def run(command):
    """Run a shell command and return its output."""
    print(f"[run] Executing: {command}")
    try:
        result = subprocess.run(command, shell=True, text=True, capture_output=True)
        if result.returncode != 0:
            print(f"[!] Command failed:\n  stdout: {result.stdout}\n  stderr: {result.stderr}")
            sys.exit(1)
        return result.stdout.strip()
    except Exception as e:
        print(f"[!] Exception running command '{command}': {e}")
        sys.exit(1)

def check_docker_installed():
    """Ensure Docker is installed."""
    try:
        subprocess.check_call(['docker', '--version'])
        print("[✓] Docker is already installed.")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[✗] Docker not found. Installing...")
        install_docker()

def install_docker():
    """Install Docker via apt."""
    try:
        subprocess.check_call(['apt-get', 'update'])
        subprocess.check_call(['apt-get', 'install', '-y', 'docker.io'])
        print("[✓] Docker installation complete.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to install Docker: {e}")
        sys.exit(1)

def install_pip():
    """Ensure pip is installed."""
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "--version"])
        print("[✓] pip is already installed.")
    except subprocess.CalledProcessError:
        print("[✗] pip not found. Attempting installation...")
        try:
            subprocess.check_call([sys.executable, "-m", "ensurepip", "--upgrade"])
            print("[✓] pip installed using ensurepip.")
        except subprocess.CalledProcessError:
            print("[✗] ensurepip failed. Trying apt...")
            try:
                subprocess.check_call(["apt-get", "update"])
                subprocess.check_call(["apt-get", "install", "-y", "python3-pip"])
                print("[✓] pip installed using apt.")
            except subprocess.CalledProcessError as e:
                print(f"[!] pip installation failed: {e}")
                sys.exit(1)

def install_docker_module():
    """Ensure Docker Python module is installed."""
    try:
        import docker
        print("[✓] Docker Python module already installed.")
    except ImportError:
        print("[✗] Docker module not found. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "docker"])

def build_topology():
    """Create containers and link them via veth pairs."""
    print("[+] Building network topology...")
    containers = ['hostA', 'hostB', 'r1', 'r2', 'r3', 'r4']
    for c in containers:
        run(f"docker rm -f {c} || true")

    for r in ['r1', 'r2', 'r3', 'r4']:
        run(f"docker run -d --privileged --name {r} frrouting/frr-custom:latest sleep infinity")
        run(f"docker exec {r} sysctl -w net.ipv4.ip_forward=1")

    for h in ['hostA', 'hostB']:
        run(f"docker run -d --name {h} --privileged ubuntu sleep infinity")

    link_pairs = [
        ("hostA", "r1", "veth-ha", "veth-r1a", "10.0.15.1/24", "10.0.15.2/24"),
        ("r1", "r2", "veth-r1r2", "veth-r2r1", "10.0.12.1/24", "10.0.12.2/24"),
        ("r2", "r3", "veth-r2r3", "veth-r3r2", "10.0.23.1/24", "10.0.23.2/24"),
        ("r1", "r4", "veth-r1r4", "veth-r4r1", "10.0.14.1/24", "10.0.14.2/24"),
        ("r4", "r3", "veth-r4r3", "veth-r3r4", "10.0.24.1/24", "10.0.24.2/24"),
        ("r3", "hostB", "veth-r3b", "veth-hb", "10.0.43.1/24", "10.0.43.2/24"),
    ]

    for left, right, veth1, veth2, ip1, ip2 in link_pairs:
        run(f"ip link add {veth1} type veth peer name {veth2}")
        left_pid = run(f"docker inspect -f '{{{{.State.Pid}}}}' {left}")
        right_pid = run(f"docker inspect -f '{{{{.State.Pid}}}}' {right}")
        run(f"ip link set {veth1} netns {left_pid}")
        run(f"ip link set {veth2} netns {right_pid}")

        for name, pid, veth, ip in [(left, left_pid, veth1, ip1), (right, right_pid, veth2, ip2)]:
            run(f"nsenter -t {pid} -n ip link set {veth} up")
            run(f"nsenter -t {pid} -n ip addr add {ip} dev {veth}")

    print("[✓] Topology built successfully.")

def install_tools_on_router(node):
    print(f"[*] Setting up tools on {node}...")

    check_tcpdump = f"docker exec {node} which tcpdump > /dev/null 2>&1"
    if os.system(check_tcpdump) == 0:
        print(f"    [✓] tcpdump already installed on {node}")
        return

    setup_commands = [
        "apt -y update",
        "apt -y install curl gnupg lsb-release",
        "curl -s https://deb.frrouting.org/frr/keys.gpg | tee /usr/share/keyrings/frrouting.gpg > /dev/null",
        "echo deb '[signed-by=/usr/share/keyrings/frrouting.gpg]' https://deb.frrouting.org/frr $(lsb_release -s -c) frr-stable | tee -a /etc/apt/sources.list.d/frr.list",
        "apt update",
        "apt -y install tcpdump",
    ]

    for cmd in setup_commands:
        print(f"    [>] {cmd}")
        os.system(f"docker exec {node} bash -c \"{cmd}\"")

def start_ospf():
    """Configure and start OSPF daemons on routers."""
    print("[+] Starting OSPF daemons...")
    client = docker.from_env()
    for r in ["r1", "r2", "r3", "r4"]:
        c = client.containers.get(r)
        c.exec_run(f"bash -c 'echo \"{DAEMONS_CONFIG.strip()}\" > /etc/frr/daemons'", privileged=True)
        c.exec_run(f"bash -c 'echo \"{FRR_CONF.strip()}\" > /etc/frr/frr.conf'", privileged=True)
        c.exec_run("chown frr:frr /etc/frr/daemons /etc/frr/frr.conf", privileged=True)
        c.exec_run("/usr/lib/frr/frrinit.sh start", privileged=True)
    print("[✓] OSPF daemons started.")

def install_ip_tools(container_name):
    """Install necessary networking tools inside a container."""
    client = docker.from_env()
    print(f"[*] Installing tools on {container_name}...")
    result = client.containers.get(container_name).exec_run(
        'bash -c "apt-get update && apt-get install -y iproute2 iputils-ping tcpdump"',
        privileged=True
    )
    print(result.output.decode())

def add_route_to_container(container, dest, gw):
    """Add a static route inside a container."""
    client = docker.from_env()
    print(f"[*] Adding route on {container}: {dest} via {gw}")
    result = client.containers.get(container).exec_run(f"ip route add {dest} via {gw}")
    print(result.output.decode())

def install_routes():
    """Set up static routes and install tools on hosts and routers."""
    for node in ["hostA", "hostB", "r1", "r4"]:
        install_ip_tools(node)

    add_route_to_container("hostA", "10.0.43.0/24", "10.0.15.2")
    add_route_to_container("hostB", "10.0.15.0/24", "10.0.43.1")
    print("[✓] Routes and tools installed.")

def set_ospf_cost(router, interface, cost):
    """Set the OSPF cost on a router interface."""
    client = docker.from_env()
    cmd = (
        f'vtysh -c "configure terminal" '
        f'-c "interface {interface}" '
        f'-c "ip ospf cost {cost}"'
    )
    print(f"[+] Setting OSPF cost on {router} {interface} -> {cost}")
    try:
        res = client.containers.get(router).exec_run(cmd, privileged=True)
        print(res.output.decode())
    except Exception as e:
        print(f"[!] Error setting OSPF cost: {e}")

def move_traffic(path='north'):
    """Shift traffic flow by modifying OSPF costs."""
    print(f"[+] Moving traffic via {path} path...")
    if path == 'north':
        set_ospf_cost("r1", "veth-r1r2", 10)
        set_ospf_cost("r1", "veth-r1r4", 100)
        set_ospf_cost("r3", "veth-r3r2", 10)
        set_ospf_cost("r3", "veth-r3r4", 100)
    elif path == 'south':
        set_ospf_cost("r1", "veth-r1r2", 100)
        set_ospf_cost("r1", "veth-r1r4", 10)
        set_ospf_cost("r3", "veth-r3r2", 100)
        set_ospf_cost("r3", "veth-r3r4", 10)
    else:
        print("[!] Invalid path. Choose 'north' or 'south'.")
        return
    print(f"[✓] OSPF cost updated. Traffic prefers {path} path.")

def main():
    print("[DEBUG] Script started")  
    if os.geteuid() != 0:
        print("[!] Script must be run as root.")
        sys.exit(1)

    install_pip()
    install_docker_module()
    check_docker_installed()
    global docker
    if docker is None:
        import docker

    parser = argparse.ArgumentParser(
        description="Orchestrator for FRR OSPF Network Topology Setup and Management"
    )
    parser.add_argument("--install-docker", action="store_true", help="Install Docker on the system")
    parser.add_argument("--build-topology", action="store_true", help="Build the container network topology")
    parser.add_argument("--start-ospf", action="store_true", help="Start OSPF routing daemons")
    parser.add_argument("--install-routes", action="store_true", help="Install IP tools and static routes")
    parser.add_argument("--move-traffic", choices=["north", "south"], help="Shift ICMP traffic path")
    
    # Show help if no arguments are provided
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    if args.install_docker:
        install_docker()
    if args.build_topology:
        build_topology()
    if args.start_ospf:
        start_ospf()
    if args.install_routes:
        install_routes()
    if args.move_traffic:
        move_traffic(args.move_traffic)

if __name__ == "__main__":
    main()
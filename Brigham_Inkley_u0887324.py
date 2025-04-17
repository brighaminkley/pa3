#!/usr/bin/env python3

import os
import sys
import subprocess
import argparse

def check_docker_installed():
    try:
        subprocess.check_call(['docker', '--version'])
        print("Docker is already installed.")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Docker is not installed. Installing Docker...")
        install_docker()

def install_pip():
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "--version"])
        print("pip is already installed.")
    except subprocess.CalledProcessError:
        print("pip not found, attempting to install pip via ensurepip...")
        try:
            subprocess.check_call([sys.executable, "-m", "ensurepip", "--upgrade"])
            print("pip installed using ensurepip.")
        except subprocess.CalledProcessError:
            print("ensurepip failed, trying apt-get install python3-pip...")
            try:
                subprocess.check_call(["apt-get", "update"])
                subprocess.check_call(["apt-get", "install", "-y", "python3-pip"])
                print("pip installed using apt.")
            except subprocess.CalledProcessError as e:
                print(f"[!] Failed to install pip via apt: {e}")
                sys.exit(1)

def install_docker():
    try:
        subprocess.check_call(['apt-get', 'update'])
        subprocess.check_call(['apt-get', 'install', '-y', 'docker.io'])
        subprocess.check_call(['docker', '--version'])
        print("Docker installation complete.")
    except subprocess.CalledProcessError as e:
        print(f"Error installing Docker: {e}")
        sys.exit(1)

def install_docker_module():
    try:
        import docker
        print("Docker Python module already installed.")
    except ImportError:
        print("Docker Python module not found, installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "docker"])

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
    print(f"[run] Executing: {command}")
    try:
        result = subprocess.run(command, shell=True, text=True, capture_output=True)
        if result.returncode != 0:
            print(f"[!] Error executing command: {command}")
            print(f"stderr: {result.stderr}")
            print(f"stdout: {result.stdout}")
            sys.exit(1)
        return result.stdout.strip()
    except Exception as e:
        print(f"[!] Exception during command execution: {e}")
        sys.exit(1)

def build_topology():
    print("[+] Building network topology...")
    containers = ['hostA', 'hostB', 'r1', 'r2', 'r3', 'r4']
    for c in containers:
        run(f"docker rm -f {c} || true")

    for r in ['r1', 'r2', 'r3', 'r4']:
        run(f"docker run -d --privileged --name {r} frrouting/frr:latest sleep infinity")
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

    print("[+] Topology built successfully.")

def start_ospf():
    print("[+] Starting OSPF daemons on routers...")
    client = docker.from_env()
    routers = ["r1", "r2", "r3", "r4"]
    for router in routers:
        container = client.containers.get(router)
        container.exec_run(f"bash -c 'echo \"{DAEMONS_CONFIG.strip()}\" > /etc/frr/daemons'", privileged=True)
        container.exec_run(f"bash -c 'echo \"{FRR_CONF.strip()}\" > /etc/frr/frr.conf'", privileged=True)
        container.exec_run("chown frr:frr /etc/frr/daemons /etc/frr/frr.conf", privileged=True)
        container.exec_run("/usr/lib/frr/frrinit.sh start", privileged=True)
    print("[+] OSPF daemons started.")

def install_ip_tools(container_name):
    client = docker.from_env()
    try:
        print(f"[*] Installing iproute2 and iputils-ping on {container_name}...")
        result = client.containers.get(container_name).exec_run(
            "apt-get update && apt-get install -y iproute2 iputils-ping"
        )
        print(f"{container_name} install result: {result.output.decode('utf-8')}")
    except Exception as e:
        print(f"[!] Error installing packages on {container_name}: {e}")

def add_route_to_container(container_name, destination, gateway):
    client = docker.from_env()
    try:
        print(f"[*] Adding route on {container_name}...")
        route_command = f"ip route add {destination} via {gateway}"
        result = client.containers.get(container_name).exec_run(route_command)
        print(f"{container_name} route add result: {result.output.decode('utf-8')}")
    except Exception as e:
        print(f"[!] Error adding route on {container_name}: {e}")

def install_routes():
    containers = ['hostA', 'hostB']
    routes = [
        {'container': 'hostA', 'destination': '10.0.43.0/24', 'gateway': '10.0.15.2'},
        {'container': 'hostB', 'destination': '10.0.15.0/24', 'gateway': '10.0.43.1'}
    ]

    for container in containers:
        install_ip_tools(container)

    for route in routes:
        add_route_to_container(route['container'], route['destination'], route['gateway'])

    print("[+] Routes installation completed.")

def move_traffic(path='north'):
    print(f"[+] Moving traffic on {path} path...")
    if path == 'north':
        run("docker exec r1 ip route add 10.0.14.0/24 via 10.0.12.2")
        run("docker exec r4 ip route del 10.0.43.0/24 || true")
    elif path == 'south':
        run("docker exec r1 ip route add 10.0.12.0/24 via 10.0.14.2")
        run("docker exec r2 ip route del 10.0.23.0/24 || true")
    else:
        print("[!] Invalid path specified.")
    print(f"[+] Traffic moved on {path} path.")

def main():
    if os.geteuid() != 0:
        print("[!] This script must be run as root.")
        sys.exit(1)

    install_pip()
    install_docker_module()
    check_docker_installed()
    import docker

    parser = argparse.ArgumentParser(description="Network Topology Orchestrator")
    parser.add_argument("--install-docker", action="store_true", help="Install Docker and setup environment")
    parser.add_argument("--build-topology", action="store_true", help="Build network topology")
    parser.add_argument("--start-ospf", action="store_true", help="Start OSPF daemons")
    parser.add_argument("--install-routes", action="store_true", help="Install routes on hosts")
    parser.add_argument("--move-traffic", choices=['north', 'south'], help="Move traffic on the specified path")

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


# #!/usr/bin/env python3

# DAEMONS_CONFIG = """zebra=yes
# bgpd=no
# ospfd=yes
# """

# FRR_CONF = """!
# hostname frr
# password zebra
# log stdout
# !
# router ospf
#  network 10.0.0.0/8 area 0
# !
# """

# import os
# import sys
# import subprocess
# import argparse
# import docker


# def run(command):
#     """Helper function to run shell commands."""
#     result = subprocess.run(command, shell=True, text=True, capture_output=True)
#     if result.returncode != 0:
#         print(f"Error: {result.stderr}")
#         sys.exit(1)
#     return result.stdout.strip()

# def check_docker():
#     try:
#         subprocess.run(['docker', '--version'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#         print("[+] Docker is already installed.")
#     except subprocess.CalledProcessError:
#         print("[-] Docker not found. Installing Docker...")
#         install_docker()

# def install_docker():
#     """Install Docker and setup the environment."""
#     print("[+] Installing Docker...")
#     run("git clone https://gitlab.flux.utah.edu/teach-studentview/cs4480-2025-s.git")
#     os.chdir("cs4480-2025-s/pa3/part1/")
#     run("./dockersetup")
#     print("[+] Docker installation complete.")

# def build_topology():
#     """Build the network topology with Docker containers."""
#     print("[+] Building network topology...")
#     containers = ['hostA', 'hostB', 'r1', 'r2', 'r3', 'r4']
#     for c in containers:
#         run(f"docker rm -f {c} || true")

#     for r in ['r1', 'r2', 'r3', 'r4']:
#         run(f"docker run -d --privileged --name {r} frrouting/frr:latest sleep infinity")

#     for r in ['r1', 'r2', 'r3', 'r4']:
#         run(f"docker exec {r} sysctl -w net.ipv4.ip_forward=1")

#     run("docker run -d --name hostA --privileged ubuntu sleep infinity")
#     run("docker run -d --name hostB --privileged ubuntu sleep infinity")

#     link_pairs = [
#         ("hostA", "r1", "veth-ha", "veth-r1a", "10.0.15.1/24", "10.0.15.2/24"),
#         ("r1", "r2", "veth-r1r2", "veth-r2r1", "10.0.12.1/24", "10.0.12.2/24"),
#         ("r2", "r3", "veth-r2r3", "veth-r3r2", "10.0.23.1/24", "10.0.23.2/24"),
#         ("r1", "r4", "veth-r1r4", "veth-r4r1", "10.0.14.1/24", "10.0.14.2/24"),
#         ("r4", "r3", "veth-r4r3", "veth-r3r4", "10.0.24.1/24", "10.0.24.2/24"),
#         ("r3", "hostB", "veth-r3b", "veth-hb", "10.0.43.1/24", "10.0.43.2/24"),
#     ]

#     for left, right, veth1, veth2, ip1, ip2 in link_pairs:
#         run(f"ip link add {veth1} type veth peer name {veth2}")

#         left_pid = run(f"docker inspect -f '{{{{.State.Pid}}}}' {left}")
#         right_pid = run(f"docker inspect -f '{{{{.State.Pid}}}}' {right}")

#         run(f"ip link set {veth1} netns {left_pid}")
#         run(f"ip link set {veth2} netns {right_pid}")

#         for name, pid, veth, ip in [(left, left_pid, veth1, ip1), (right, right_pid, veth2, ip2)]:
#             run(f"nsenter -t {pid} -n ip link set {veth} up")
#             run(f"nsenter -t {pid} -n ip addr add {ip} dev {veth}")

#     run("docker exec hostA apt-get update -y && apt-get install iproute2 -y")
#     run("docker exec hostB apt-get update -y && apt-get install iproute2 -y")

#     print("[+] Topology built successfully.")

# def start_ospf():
#     print("[+] Starting OSPF daemons on routers...")
#     client = docker.from_env()
#     routers = ["r1", "r2", "r3", "r4"]

#     for router in routers:
#         container = client.containers.get(router)

#         # Write daemons config to container
#         container.exec_run("bash -c 'echo \"{}\" > /etc/frr/daemons'".format(DAEMONS_CONFIG.strip()), privileged=True)

#         # Write frr.conf to container
#         container.exec_run("bash -c 'echo \"{}\" > /etc/frr/frr.conf'".format(FRR_CONF.strip()), privileged=True)

#         # Set ownership to frr user/group
#         container.exec_run("chown frr:frr /etc/frr/daemons /etc/frr/frr.conf", privileged=True)

#         # Start FRR daemons
#         container.exec_run("/usr/lib/frr/frrinit.sh start", privileged=True)

#     print("[+] OSPF daemons started.")

# def install_routes():
#     """Install routes on hosts."""
#     print("[+] Installing routes on hosts...")
#     try:
#         output = run("docker exec hostA ip route add 10.0.43.0/24 via 10.0.15.2")
#         print(f"Output: {output}")
#         output = run("docker exec hostB ip route add 10.0.15.0/24 via 10.0.43.1")
#         print(f"Output: {output}")
#         print("[+] Routes installed.")
#     except Exception as e:
#         print(f"Error installing routes: {e}")


# def move_traffic(path='north'):
#     """Move traffic between north and south path."""
#     print(f"[+] Moving traffic on {path} path...")
    
#     # Remove any existing routes before adding new ones
#     if path == 'north':
#         run("docker exec r1 ip route del 10.0.12.0/24")  # Remove the existing route
#         run("docker exec r2 ip route del 10.0.23.0/24")
#         run("docker exec r3 ip route del 10.0.15.0/24")
        
#         # Add routes for North path (using the correct network names for each segment)
#         run("docker exec r1 ip route add 10.0.12.0/24 via 10.0.14.2")
#         run("docker exec r2 ip route add 10.0.23.0/24 via 10.0.12.2")
#         run("docker exec r3 ip route add 10.0.15.0/24 via 10.0.23.2")
        
#     elif path == 'south':
#         run("docker exec r1 ip route del 10.0.24.0/24")
#         run("docker exec r4 ip route del 10.0.43.0/24")
#         run("docker exec r3 ip route del 10.0.15.0/24")
        
#         # Add routes for South path (using the correct network names for each segment)
#         run("docker exec r1 ip route add 10.0.24.0/24 via 10.0.14.2")
#         run("docker exec r4 ip route add 10.0.43.0/24 via 10.0.24.2")
#         run("docker exec r3 ip route add 10.0.15.0/24 via 10.0.43.2")
        
#     else:
#         print("[!] Invalid path specified.")
    
#     print(f"[+] Traffic moved on {path} path.")


# def main():
#     parser = argparse.ArgumentParser(description="Network Topology Orchestrator")
#     parser.add_argument("--install-docker", action="store_true", help="Install Docker and setup environment")
#     parser.add_argument("--build-topology", action="store_true", help="Build network topology")
#     parser.add_argument("--start-ospf", action="store_true", help="Start OSPF daemons")
#     parser.add_argument("--install-routes", action="store_true", help="Install routes on hosts")
#     parser.add_argument("--move-traffic", choices=['north', 'south'], help="Move traffic on the specified path")
    
#     args = parser.parse_args()

#     if args.install_docker:
#         install_docker()
#     if args.build_topology:
#         build_topology()
#     if args.start_ospf:
#         start_ospf()
#     if args.install_routes:
#         install_routes()
#     if args.move_traffic:
#         move_traffic(args.move_traffic)

# if __name__ == "__main__":
#     main()
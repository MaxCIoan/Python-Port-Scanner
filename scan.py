# scan.py

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from udp_probes import get_probe, get_probe_service

# -----------------------------
# TCP scan
# -----------------------------
def scan_tcp(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            return (port, "tcp", "open")
        else:
            return (port, "tcp", "closed")
    except:
        return (port, "tcp", "open|filtered")


# -----------------------------
# UDP scan
# -----------------------------
def scan_udp(ip, port):

    retries = 2
    timeout = 1

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        probe = get_probe(port)

        for _ in range(retries):

            sock.sendto(probe, (ip, port))

            try:
                sock.recvfrom(1024)
                sock.close()
                return (port, "udp", "open")

            except socket.timeout:
                continue

        sock.close()
        return (port, "udp", "open|filtered")

    except ConnectionRefusedError:
        return (port, "udp", "closed")

    except:
        return (port, "udp", "open|filtered")

# -----------------------------
# Threaded scan runner
# -----------------------------
def run_scan(ip, ports, scan_type):
    results = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = []
        for port in ports:
            if scan_type in ("tcp", "tcp+udp"):
                futures.append(executor.submit(scan_tcp, ip, port))
            if scan_type in ("udp", "tcp+udp"):
                futures.append(executor.submit(scan_udp, ip, port))
        for future in as_completed(futures):
            results.append(future.result())
    return sorted(results, key=lambda x: (x[0], x[1]))


# -----------------------------
# Display results
# -----------------------------
def display_results(results, display_mode):
    print("\nPORT     PROTO   STATE           SERVICE")
    print("----------------------------------------------")
    for port, proto, state in results:
        # Mode 1: open + open|filtered
        if display_mode == 1 and state == "closed":
            continue
        # Mode 3: only open
        if display_mode == 3 and state != "open":
            continue

        service = ""
        if proto == "tcp":
            try:
                service = socket.getservbyport(port, "tcp")
            except:
                service = ""
        if proto == "udp":
            service = get_probe_service(port)

        print(f"{port:<8}{proto:<8}{state:<15}{service}")


# -----------------------------
# Main menu
# -----------------------------
def main():
    ip = input("Target IP: ")

    print("\nScan type:")
    print("1 - TCP")
    print("2 - UDP")
    print("3 - TCP + UDP")
    choice = input("Choice: ")

    if choice == "1":
        scan_type = "tcp"
    elif choice == "2":
        scan_type = "udp"
    else:
        scan_type = "tcp+udp"

    print("\nPort option:")
    print("1 - Single port")
    print("2 - Port range")
    port_choice = input("Choice: ")

    if port_choice == "1":
        port = int(input("Port: "))
        ports = [port]
    else:
        start = int(input("Start port: "))
        end = int(input("End port: "))
        ports = list(range(start, end + 1))

    # -----------------------------
    # Display mode menu
    # -----------------------------
    print("\nDisplay mode:")
    print("1 - Show open + open|filtered")
    print("2 - Show open + open|filtered + closed")
    print("3 - Show only fully open")
    display_mode = int(input("Choice: "))

    print("\nScanning...\n")
    results = run_scan(ip, ports, scan_type)
    display_results(results, display_mode)


if __name__ == "__main__":
    main()
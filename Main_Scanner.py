import socket
import time
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from udp_probes import get_probe, get_probe_service

SCAN_RESULTS_PATTERN = r"^scan_results_(\d+)\.txt$"

#===========================================================
# All the functions created in this section from line 15-287
#-----------------------------
#Sorts the filename order to show 1 as the top of the list
#-----------------------------

def get_scan_files():
    """
    Finds saved scan files and returns them sorted by numeric filename.
    """
    numbered_files = []
    for filename in os.listdir("."):
        match = re.match(SCAN_RESULTS_PATTERN, filename)
        if match:
            numbered_files.append((int(match.group(1)), filename))
    return sorted(numbered_files, key=lambda x: x[0])

#-----------------------------
#
#-----------------------------

def get_scanned_targets():
    """
    Maps previously scanned targets to their saved file numbers from scan file headers.
    """
    scanned_targets = {}
    for file_number, filename in get_scan_files():
        with open(filename, "r") as f:
            first_line = f.readline().strip()
        if first_line.startswith("Scan results for host:"):
            scanned_ip = first_line.split(":", 1)[1].strip()
            scanned_targets[scanned_ip] = file_number
    return scanned_targets

#-----------------------------
#This counts what should the file number be
#-----------------------------

def get_next_scan_file_number():
    """
    Returns the next sequential scan file number based on existing saved scan files.
    """
    scan_files = get_scan_files()
    if not scan_files:
        return 1
    return scan_files[-1][0] + 1

# -----------------------------
# Searches for and sets the nmming concvention for the files
# -----------------------------

def get_next_available_scan_filename():
    """
    Finds the next available scan filename without overwriting existing result files.
    """
    file_number = get_next_scan_file_number()
    filename = f"scan_results_{file_number}.txt"
    while os.path.exists(filename):
        file_number += 1
        filename = f"scan_results_{file_number}.txt"
    return file_number, filename

# -----------------------------
# Scan results and writes all the results to a file with the target details and the scan type and the ports that were scanned as well
# -----------------------------

def save_scan_results(target_ip, results, scan_type, ports):
    """
    Saves current scan results with target details to a new numbered text file.
    """
    _, filename = get_next_available_scan_filename()
    start = time.time()

    if not ports:
        port_summary = "None"
    elif len(ports) == 1:
        port_summary = str(ports[0])
    else:
        min_port = min(ports)
        max_port = max(ports)
        if ports == list(range(min_port, max_port + 1)):
            port_summary = f"{min_port}-{max_port}"
        else:
            port_summary = ", ".join(str(port) for port in ports)

    with open(filename, "w") as f:
        f.write(f"Scan results for host: {target_ip}\n")
        f.write(f"Scan type: {scan_type}\n")
        f.write(f"Ports: {port_summary}\n")
        f.write("\nPort status:\n")
        f.write(f"{'PORT':<8}{'PROTO':<8}{'STATE':<15}{'SERVICE'}\n")
        f.write("-" * 50 + "\n")
        for port, proto, state in results:
            service = ""
            try:
                service = socket.getservbyport(port, proto)
            except:
                service = get_probe_service(port) or ""
            f.write(f"{port:<8}{proto:<8}{state:<15}{service}\n")

    end = time.time()
    return filename, end - start

# -----------------------------
# TCP scan
# -----------------------------

def scan_tcp(ip, port):
    """
    Scans one TCP port and returns a standardized result containing port, protocol, and state.
    """
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
        return (port, "tcp", "filtered")
    
# -----------------------------
# UDP scan
# -----------------------------

def scan_udp(ip, port):
    """
    Scans one UDP port with retries and returns a standardized port state result.
    """

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
        return (port, "udp", "filtered")

    except ConnectionRefusedError:
        return (port, "udp", "closed")

    except:
        return (port, "udp", "filtered")

# -----------------------------
# Threaded scan runner
# -----------------------------

def run_scan(ip, ports, scan_type):
    """
    Runs selected scan types concurrently across ports and returns sorted scan results.
    """
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
    """
    Prints scan results in a table and filters output using the chosen display mode.
    """
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
        try:
            service = socket.getservbyport(port, proto)
        except:
            service = ""

        print(f"{port:<8}{proto:<8}{state:<15}{service}")
        
# -----------------------------
# Main menu
# -----------------------------

def main():
    """
    Collects scan inputs, runs the scan, displays results, and optionally saves the output.
    """
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
    print("1 - Show open + filtered")
    print("2 - Show open + filtered + closed")
    print("3 - Show only fully open")
    display_mode = int(input("Choice: "))

    print("\nScanning...\n")
    results = run_scan(ip, ports, scan_type)
    display_results(results, display_mode)

    save_choice = input("\nDo you want to save this scan to a file? (y/n): ").strip().lower()
    if save_choice == "y":
        filename, elapsed = save_scan_results(ip, results, scan_type, ports)
        print(f"Scan saved to {filename}")
        print(f"Save time {elapsed:.2f} seconds")
    else:
        print("Scan not saved.")

    print(input("Press Enter to return to main menu..."))
    
# -----------------------------
# Ping and OS commands for reconnaissance
# -----------------------------

def ping_host():
    target = input("Enter IP or hostname to ping:")
    if os.name =="nt":
        os.system(f"ping {target}")
    else:
        os.system(f"ping -c 4 {target}")

def dns_lookup():
    domain = input("Enter domain name to look up:")
    os.system(f"nslookup {domain}")

def show_arp():
    os.system("arp -a")

#===========================================================
# Main loop starts after all the function definitions from line 297 - 437

play = True
while play == True:
    banner = r"""
    ███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗
    ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝
    ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║██████╔╝█████╔╝
    ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔══██╗██╔═██╗
    ██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗
    ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝

    ██████╗  ██████╗ ██████╗ ████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗  
    ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
    ██████╔╝██║   ██║██████╔╝   ██║       ███████╗██║     ███████║██╔██╗ ██║
    ██╔═══╝ ██║   ██║██╔══██╗   ██║       ╚════██║██║     ██╔══██║██║╚██╗██║
    ██║     ╚██████╔╝██║  ██║   ██║       ███████║╚██████╗██║  ██║██║ ╚████║
    ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

                [1] Start Scan
                [2] Export to file results
                [3] Ping target and os comands for reconnaissance
                [4] Quit 
    """
    print(banner)
    print("Main Menu :")
    print("="*90)
    answer = input(f"1. Start scan \n2. Export to file results \n3. Ping target and os commands for reconnaissance \n4. Exit\n")
    #===============================================================================================================================
    # This section is for scanning all ports or specific ports and showing the results of the scan
    # Accepts a target IP and a port range as input
    # Reports each port as OPEN, CLOSED, or FILTERED
    
    if answer == "1" :

        if __name__ == "__main__":
            main()
#===============================================================================================================================
    # this part will be dealing with exporting the results of the scan to a file and showing the results in the terminal as well
    #Saves results to a file (.txt, .json, or .csv)
    elif answer == "2":
        while True:
            print("\nScan Results Submenu:")
            print("1. View saved scan file")
            print("2. Back to main menu")
            sub_answer = input("Select an option: ").strip()

            if sub_answer == "1":
                scan_files = get_scan_files()
                if not scan_files:
                    print("No saved scan files found.")
                    continue

                print("\nAvailable scan files:")
                for file_number, filename in scan_files:
                    print(f"{file_number}. {filename}")

                selected_number = input("Enter file number to open: ").strip()
                if not selected_number.isdigit():
                    print("Invalid selection. Enter a valid number.")
                    continue

                selected_number = int(selected_number)
                selected_filename = None
                for file_number, filename in scan_files:
                    if file_number == selected_number:
                        selected_filename = filename
                        break

                if selected_filename is None:
                    print("That file number does not exist.")
                    continue

                print(f"\nContents of {selected_filename}:")
                with open(selected_filename, "r") as f:
                    print(f.read())

            elif sub_answer == "2":
                break
            else:
                print("Invalid option. Please choose 1 or 2.")
           
#==============================================================================================================================
    # This section is for pinging and os commands.
    elif answer == "3" :

        while True:
            print("= 30")
            print("1 - Ping a Host")
            print("2 - DNS Lookup")
            print("3 - Show ARP Table")
            print("4 - Back To Main Menu")
            print("=30")

            sub_choice = input("Choose an option")
            
            if sub_choice =="1":
                ping_host()
            elif sub_choice =="2":
                dns_lookup()
            elif sub_choice =="3":
                show_arp()
            elif sub_choice =="4":
                break
            else:
                print("Invalid option")
#===============================================================================================================================

    elif answer == "4" :
        
        banner = r"""
        
        ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⡿⣿⣿⡿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⣻⣻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣟⡽⣯⣻⣻⡽⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⣻⣻
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⡿⣿⣿⣿⣿⣿⣿⡿⣻⣻⣻⣻⣻⣻⡽⣯⣟⢷⠍⠟⠉⠛⢿⢿⣻⣻⢿⣿⣿⣯⣻⡽⣯⣻⣻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣻⢯
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣻⣻⣻⣻⡟⡅⠀⠀⠀⠠⠀⠀⠆⡹⣻⣻⡽⣯⣻⡽⣯⣻⡽⣻⣻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣻⣻⣻
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣻⣿⡟⡛⡜⡜⣎⢦⢶⣖⡴⡀⠠⣿⣿⣿⣟⣟⣟⣟⣟⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣻⣻⣻⣻
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣻⣻⢆⢭⢎⢎⢞⡝⣝⡽⡽⡣⢂⣟⢯⢯⢯⣿⣻⣻⡽⣻⡽⣻⣻⣿⣿⣿⣿⣿⣿⣿⡿⣟⣿⣿⣿⣿⣻
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⣟⢧⡒⡔⢆⢯⢎⠚⡜⡇⣼⣿⣿⣯⣻⣻⣻⣻⢯⣿⣿⣻⣻⣻⣻⢿⣿⣿⣿⣿⡿⣻⣻⣻⣟⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⢹⢧⢣⢣⠡⡋⡯⣫⢯⡹⣹⣿⣿⣿⣿⣯⣻⣻⣻⣿⣿⣻⣻⣻⣿⣟⣟⢿⣿⣿⣿⣿⣻⢿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠧⢣⢢⢌⣍⡹⡽⣹⣽⣿⣿⣿⣿⣿⡽⣯⣻⢯⣻⢯⣻⣻⣿⣿⣿⣿⣻⣻⣻⣻⢿⢿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣟⡽⣍⢎⢎⢝⢏⢏⣝⢿⣿⣿⣿⣿⣿⣿⣻⡽⣯⣻⣻⣿⣿⣟⢿⣿⢿⣻⣻⣿⣿⢿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⣿⣿⣟⣟⣟⡜⡜⡜⡝⡭⣫⢫⠂⢫⣿⣿⣿⣟⢯⣻⣻⣻⡽⣻⣿⣿⣿⣟⣿⣿⣿⣻⣟⣟⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⢿⡿⣿⢿⡿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⣿⣿⣿⡿⡽⡻⡿⣇⢣⢣⠱⡱⡱⣽⣿⠀⠀⠀⠀⠐⢉⠍⡛⢿⢯⣻⣻⣿⣿⡿⣿⣿⣿⣿⣟⣟⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣟⢿⣿⣿⣿⡿⣿⣿⣟⢿⣻⣻⡿⣏⢋⠀⠀⠀⣹⣻⡇⢣⠱⣥⣻⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣿⣻⣿⣿⣿⣟⣟⣟⡽⣻⣿⡿⡿⣿⣿⣿
⣿⣿⣿⣿⣿⢿⣿⣿⣿⢿⣻⣿⢿⣿⣿⢿⣻⣻⣻⡃⠀⠀⠀⠀⠀⠀⠠⠠⡣⢢⠱⡉⠙⠛⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣻⡽⣻⣿⢯⣻⣿⣿⢯⣻⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⢿⣻⣻⣿⣟⣟⣟⣿⣿⣿⣿⣿⡿⣟⣟⠄⠀⠀⠀⠀⠀⠀⠀⢀⢆⡑⠡⠉⠋⠖⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣻⢯⣻⡽⣻⣻⡿⣯⢿⣿⣿⣿⣿⣿
⣿⣻⣟⣟⣿⣿⣿⣿⣟⣟⣟⣟⣿⣿⣿⣿⣟⣟⡽⡄⠀⠀⠀⠀⠀⠀⠀⢀⠁⣯⠚⠹⠶⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣻⢯⢯⣻⣿⣿⣻⣻⣻⣿⣿⣿⣿⣿
⣿⣟⢿⣿⣿⣿⣿⣿⣻⣿⡿⣻⣻⣿⣿⣿⢿⣻⢯⠀⠀⠀⠀⠀⠀⠀⠀⠀⠛⣟⠖⡖⡤⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⢿⣻⣿⣻⣿⣿⣿⣿⣿⣻⢯⣻⣻⣻
⣿⣻⣻⣿⣿⣿⣿⣻⣽⣿⣿⣟⣟⢿⣿⣿⡿⣻⣻⠀⠀⠀⠀⠀⠀⠀⠀⠀⢦⢢⣠⣀⠀⠀⠀⠀⠩⡛⡝⡜⡖⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢿⣿⣻⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣻⣻⣻⣿⣿⡿⣻⣿⣿⣻⣻⣿⣿⡿⣿⣻⣻⣻⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⡜⠈⠁⠀⠀⠀⠀⠀⠌⣌⢎⡜⡜⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣻⣿⣿⡿⣟⢿⣿⣿⣿
⣟⣿⣿⣿⡽⡽⡽⣻⣹⡽⣿⣿⣿⣻⣻⣻⣻⡽⣻⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⢢⠣⠒⠀⠀⠀⠀⠀⠀⠎⢎⢎⢎⢎⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣟⡽⣿⣿⣻⣻⣻⢿⣿⣿
⣿⣿⢿⣿⣯⣫⣏⢯⣫⣿⣿⣿⣿⣟⣟⣟⣟⡽⡽⠀⡀⠀⠀⠀⠀⢀⢀⠀⠰⡰⠤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡝⡽⡽⣿⣿⣿⣻⡝⡽
⣯⣯⣯⣯⢯⣫⢫⣻⡿⣻⣿⣿⣿⣿⣿⣻⡽⡽⣭⠂⠀⡰⡱⠡⠢⢂⠆⠀⢠⠰⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⢯⢫⣫⡿⣻⣿⣿⣿⣻⡹
⡿⡿⣻⣻⣻⢭⣚⢧⢫⣻⣿⣿⡿⡽⡽⡽⡽⣹⣝⢇⠄⠀⠀⠄⠄⠄⡐⠀⠄⡐⠐⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡝⣝⡽⣹⢽⢯⡻⣻⣟⢯⢫⣚⣟⣟⣟⣟⣟⣟⡝
⣯⣻⡽⣯⣻⡜⡵⡽⣎⢭⣻⡝⡽⣽⡽⣝⣝⣝⡝⣗⢭⢎⠀⠀⠂⠂⠀⠀⠀⡐⠐⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣹⣝⣝⡝⣝⡽⡽⡹⣚⠵⡭⢯⢯⢯⣻⡽⡽⣣
⣟⣟⡽⣯⢯⢎⢎⢯⣏⡗⡝⣝⡽⣻⢯⣫⢫⢫⣫⣻⢯⡳⡱⡱⡱⠀⠀⠀⠀⠠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⡝⡝⡝⣝⡝⡝⡭⣫⢫⢭⣚⣝⣝⣝⡽⣹⣹⢧
⢏⠯⢫⢫⢫⢪⢎⢯⢏⠳⡹⡹⣻⡿⡯⣫⢫⡹⡹⡽⡽⡹⡸⡜⡄⠀⠀⢀⢂⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡭⡭⣫⡹⡹⡭⣫⢫⢫⣚⡜⡝⡝⣝⣝⢽⡹⡭
"""
        print(banner)
        print("Good bye")
        play = False
                

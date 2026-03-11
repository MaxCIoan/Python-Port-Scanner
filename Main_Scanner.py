import socket
import time
import os
import re

from concurrent.futures import ThreadPoolExecutor, as_completed




class Begining:
    
    def __init__(self, numb,listt,arrays):
    
        self.numb = numb
        self.listt = listt
        self.arrays = arrays
    
    def lenumber(self,numbers_123):
        self.numbers_123 = numbers_123
        numbers_123 = [1,2,3,4,5,6,7,8,9,0]
        
        return numbers_123
        
    def lelistt(self):
        
        self.listt = {"Port B" : 23 , "Port A": 22, "Port C" : 448 , "Port D" : 1048}
        
        self.listt["Port I"]= 81

        return self.listt
    
    def learrays(self):
        
        for i in self.lenumber(1) :
            
            i += 1
            while i <= 2 :
                
                i += 1  

    def __str__(self):
        
        return f"\n {self.learrays()} \n {self.lenumber(1)} \n"
UDP_PROBES = {

    53: (
        "domain",
        b"\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x06google\x03com\x00\x00\x01\x00\x01"
    ),

    69: (
        "tftp",
        b"\x00\x01test\x00octet\x00"
    ),

    111: (
        "rpcbind",
        b"\x80\x00\x00\x28" + 40 * b"\x00"
    ),

    123: (
        "ntp",
        b"\x1b" + 47 * b"\x00"
    ),

    137: (
        "netbios-ns",
        b"\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"
    ),

    161: (
        "snmp",
        b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04"
        b"\x71\xb4\xb5\x68\x02\x01\x00\x02\x01\x00\x30\x0b"
        b"\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"
    ),

    1900: (
        "ssdp",
        b"M-SEARCH * HTTP/1.1\r\nST:ssdp:all\r\nMX:2\r\nMAN:\"ssdp:discover\"\r\n\r\n"
    ),

    500: (
        "isakmp",
        b"\x00" * 20
    ),

    520: (
        "rip",
        b"\x01\x01\x00\x00"
    ),

    2049: (
        "nfs",
        b"\x80\x00\x00\x28" + 40 * b"\x00"
    )

}

def get_probe(port):
    """Return UDP probe packet for a port"""
    if port in UDP_PROBES:
        return UDP_PROBES[port][1]

    return b"\x00"


def get_probe_service(port):
    """Return service name from probe database"""
    if port in UDP_PROBES:
        return UDP_PROBES[port][0]

    return None
test_four =  Begining("Numb","List","array")



#print(test_four.learrays())
#print(f"Each port number per line :\n{test_four.lelistt()}")
#print(f"Each port number per line :\n{test_four.lenumber(1)}")

SCAN_RESULTS_PATTERN = r"^scan_results_(\d+)\.txt$"


def port_scan(target_ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        try:
            s.connect((target_ip, port))
            return True
        except:
            return False


def get_scan_files():
    numbered_files = []
    for filename in os.listdir("."):
        match = re.match(SCAN_RESULTS_PATTERN, filename)
        if match:
            numbered_files.append((int(match.group(1)), filename))
    return sorted(numbered_files, key=lambda x: x[0])


def get_scanned_targets():
    scanned_targets = {}
    for file_number, filename in get_scan_files():
        with open(filename, "r") as f:
            first_line = f.readline().strip()
        if first_line.startswith("Scan results for host:"):
            scanned_ip = first_line.split(":", 1)[1].strip()
            scanned_targets[scanned_ip] = file_number
    return scanned_targets


def get_next_scan_file_number():
    scan_files = get_scan_files()
    if not scan_files:
        return 1
    return scan_files[-1][0] + 1


def save_scan_results(target_ip):
    file_number = get_next_scan_file_number()
    filename = f"scan_results_{file_number}.txt"
    start = time.time()

    with open(filename, "w") as f:
        f.write(f"Scan results for host: {target_ip}\n")
        f.write("Port status:\n")
        for port in range(30):
            if port_scan(target_ip, port):
                f.write(f"port {port} is open\n")
            else:
                f.write(f"port {port} is closed\n")

    end = time.time()
    return filename, end - start

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
                [3] Ping target and show list of scans
                [4] Quit 
    """
    print(banner)
    print("Main Menu :")
    print("="*90)
    answer = input(f"1. Start scan \n2. Export to file results \n3. Ping target and show list of scans \n4. Exit\n")
    #===============================================================================================================================
    # This section is for scanning all ports or specific ports and showing the results of the scan
    # Accepts a target IP and a port range as input
    # Reports each port as OPEN, CLOSED, or FILTERED
    
    if answer == "1" :
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

                #probe = get_probe(port)

                for _ in range(retries):

                    #sock.sendto(probe, (ip, port))

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
                try:
                    service = socket.getservbyport(port, proto)
                except:
                    service = ""

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
            print(input("Press Enter to return to main menu..."))

        if __name__ == "__main__":
            main()
#===============================================================================================================================
    # this part will be dealing with exporting the results of the scan to a file and showing the results in the terminal as well
    #Saves results to a file (.txt, .json, or .csv)
    elif answer == "2":
        while True:
            print("\nScan Results Submenu:")
            print("1. Start new scan and save")
            print("2. View saved scan file")
            print("3. Back to main menu")
            sub_answer = input("Select an option: ").strip()

            if sub_answer == "1":
                start_new_scan = input("Do you want to start a new scan? (y/n): ").strip().lower()
                if start_new_scan != "y":
                    print("Scan canceled.")
                    continue

                target = input("What target do you want to scan?: ").strip()
                try:
                    target_ip = socket.gethostbyname(target)
                except socket.gaierror:
                    print("Could not resolve target hostname.")
                    continue

                scanned_targets = get_scanned_targets()
                if target_ip in scanned_targets:
                    previous_file = scanned_targets[target_ip]
                    print(f"Target {target_ip} was already scanned in scan_results_{previous_file}.txt")
                    continue

                filename, elapsed = save_scan_results(target_ip)
                print(f"Scan completed for {target_ip}")
                print(f"Saved to {filename}")
                print(f"Time taken {elapsed:.2f} seconds")

            elif sub_answer == "2":
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

            elif sub_answer == "3":
                break
            else:
                print("Invalid option. Please choose 1, 2, or 3.")
        
#==============================================================================================================================
    # This section is for showing the list of port numbers and allowing the user to add new port number
    elif answer == "3" :
        
        def ping_host():
            target = input("Enter IP or hostname to ping: ")
            os.system(f"nslookup {target}")

        choice = input("Press 3 to ping a host: ")
        ping_host()
#===============================================================================================================================

    elif answer == "4" :
        print("Good bye")
        play = False
                

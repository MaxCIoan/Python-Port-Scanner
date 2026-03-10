import socket
import time

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

test_four =  Begining("Numb","List","array")

#print(test_four.learrays())
#print(f"Each port number per line :\n{test_four.lelistt()}")
#print(f"Each port number per line :\n{test_four.lenumber(1)}")

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
                [3] List of port numbers
                [4] Quit 
    """
    print(banner)
    print("Main Menu :")
    print("="*90)
    answer = input(f"1. Start scan \n2. Export to file results \n3. List of port numbers \n4. Exit\n")
    #===============================================================================================================================
    # This section is for scanning all ports or specific ports and showing the results of the scan
    # Accepts a target IP and a port range as input
    # Reports each port as OPEN, CLOSED, or FILTERED
    
    if answer == "1" :
        # s for socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        target = input('What you want to scan?: ')

        target_ip = socket.gethostbyname(target)
        print('Starting scan on host:', target_ip)

        def port_scan(port):
            try:
                s.connect((target_ip, port))
                return True
            except:
                return False

        start = time.time()

        for port in range(30):
            if port_scan(port):
                print(f'port {port} is open')
            else:
                print(f'port {port} is closed')

        end = time.time()
        print(f'Time taken {end-start:.2f} seconds')
#===============================================================================================================================
    # this part will be dealing with exporting the results of the scan to a file and showing the results in the terminal as well
    #Saves results to a file (.txt, .json, or .csv)
    elif answer == "2":
        
        with open('scan_results.txt', 'w') as f:
            f.write(f'Scan results for host: {target_ip}\n')
            f.write(f'Time taken: {end-start:.2f} seconds\n')
            f.write('Open ports:\n')
            for port in open_ports:
                f.write(f'{port}\n')
                print(f'port {port} is open')
                
        continue 
    question = input("Do you want to continue? (y/n) : ")
    if question == "y" :
        continue
    
#==============================================================================================================================
    # This section is for showing the list of port numbers and allowing the user to add new port number
    elif answer == "3" :
        
        for i in test_four.lelistt() :
            print(f"{i}: {test_four.lelistt()[i]}")
            
        for item in test_four.lelistt() :
            print(f"{item}: {test_four.lelistt()[item]}")
            appends = test_four.lelistt()
            
        new_port = input("Enter the new port name : ")
        new_port_number = input("Enter the new port number : ")
        
        test_four.lelistt()[new_port] = int(new_port_number)
        print(f"New list : {test_four.lelistt()}")  

#===============================================================================================================================

    elif anss == "4" :
        print("Good bye")
        play = False
                
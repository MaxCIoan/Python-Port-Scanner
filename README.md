App for port-scanning

Port Scanner(with threading)
A Python-based network scanning application that enables users to detect open TCP and UDP ports, analyze service availability, and perform basic reconnaissance on target hosts.


🧠 Application Overview
Port Scanner app is an interactive network scanning application written in Python (400+ lines of code) that allows users to detect open TCP and UDP ports, perform basic reconnaissance, and save scan results for later analysis.

It provides:

• TCP and UDP port scanning
• Detection of open, closed, and filtered ports
• Multi-threaded scanning for faster results
• Service identification for common ports
• Interactive command-line interface for scan configuration
• Built-in reconnaissance tools such as ping, DNS lookup, and ARP table viewing
• Automatic saving of scan results for later analysis and viewing

🚀🔹 Port Scanning Engine
Scan target hosts for open network ports
Supports TCP and UDP scanning
Detect open, closed, and filtered ports
Identify common services running on discovered ports

🔹 Multi-Threaded Scanning
Uses concurrent threads to scan multiple ports simultaneously
Significantly faster than sequential scanning
Efficient handling of large port ranges

🔹 Interactive Scan Interface
Command-line menu for selecting scan options
Choose between TCP, UDP, or combined scans
Scan a single port or a custom port range
Flexible display modes for scan results

🔹 Result Management
Automatically saves scan results to numbered files
Prevents overwriting previous scan data
Allows users to review previous scans directly from the application

🔹 Reconnaissance Tools
Built-in utilities to assist network exploration

Includes:

Host ping testing

DNS lookup

Viewing the ARP table of nearby devices

🔹 Service Identification
Attempts to detect the likely service running on each discovered port
Uses system service databases and probe-based detection when available

🔹 Modular Structure
Organized function-based architecture
Clear separation between:

scanning logic

result storage

display and user interaction

Designed for readability, maintainability, and extensibility


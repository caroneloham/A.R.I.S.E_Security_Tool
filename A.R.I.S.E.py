import tkinter as tk
from tkinter import messagebox, scrolledtext
import threading
import subprocess
import re
import nmap
class SecurityScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.configure_window()

        self.create_ip_input_section()
        self.create_scan_button()
        self.create_output_section()

    def configure_window(self):
        self.title("ARISE Security Tool")
        self.geometry("800x600")

    def create_ip_input_section(self):
        self.target_ip_label = tk.Label(self, text="Enter Target IP Address:")
        self.target_ip_label.pack(pady=10)
        self.target_ip_entry = tk.Entry(self)
        self.target_ip_entry.pack(pady=5)

    def create_scan_button(self):
        self.initiate_scan_button = tk.Button(self, text="Start Scan", command=self.initiate_scan_process)
        self.initiate_scan_button.pack(pady=10)

    def create_output_section(self):
        self.scan_results_output = scrolledtext.ScrolledText(self, width=70, height=25)
        self.scan_results_output.pack(pady=10)

    def display_scan_result(self, text):
        self.scan_results_output.insert(tk.END, text + "\n")
        self.scan_results_output.see(tk.END)

    def initiate_scan_process(self):
        ip_address = self.target_ip_entry.get()
        if not ip_address:
            messagebox.showwarning("Warning", "Please enter an IP address.")
            return
        threading.Thread(target=self.execute_scans, args=(ip_address,), daemon=True).start()

    def execute_scans(self, ip_address):
        self.scan_network_ports(ip_address)
        self.run_testssl_scan(ip_address)
        self.perform_nmap_scan(ip_address)
        self.perform_dirb_scan(ip_address)

    def scan_network_ports(self, ip_address):
        port_scanner = nmap.PortScanner()
        port_scanner.scan(ip_address, arguments='-sV')  # sV for version detection
        for host in port_scanner.all_hosts():
            for protocol in port_scanner[host].all_protocols():
                port_list = list(port_scanner[host][protocol].keys())
                for port in port_list:
                    service_name = port_scanner[host][protocol][port]['name']
                    service_version = port_scanner[host][protocol][port]['version']
                    self.display_scan_result(f"Service: {service_name}, Version: {service_version}")
                    # Add your exploit search logic here


    def run_testssl_scan(self, ip_address):
        testssl_command = f"./testssl.sh --quiet {ip_address}"
        try:
            testssl_output = subprocess.check_output(testssl_command, shell=True, text=True)
            self.display_scan_result("Testssl.sh Result:\n" + testssl_output)
        except subprocess.CalledProcessError as e:
            self.display_scan_result("Testssl.sh Error: " + str(e))

    def perform_nmap_scan(self, ip_address):
        self.display_scan_result("Starting Nmap Scan...")
        try:
            nmap_result = subprocess.check_output(["nmap", "-sV", ip_address], text=True)
            self.display_scan_result(nmap_result)
            services = re.findall(r'(\d+/tcp\s+open\s+\S+)\s+(.+)', nmap_result)
            for service in services:
                port, service_name = service
                self.display_scan_result(f"Searching exploits for: {service_name}...")
                try:
                    exploits = subprocess.check_output(["searchsploit", service_name], text=True)
                    self.display_scan_result(exploits)
                except subprocess.CalledProcessError:
                    self.display_scan_result("Searchsploit error or no exploits found.")
        except Exception as e:
            self.display_scan_result(f"Nmap Scan Error: {e}")

    def perform_dirb_scan(self, ip_address):
        self.display_scan_result("Starting Dirb Scan...")
        try:
            dirb_cmd = ["dirb", f"http://{ip_address}", "-w", "-z", "10"]
            dirb_process = subprocess.Popen(dirb_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            dirb_output = ""
            for _ in range(15):  # Reading the first 15 lines of Dirb output
                line = dirb_process.stdout.readline()
                if not line:
                    break
                dirb_output += line
            self.display_scan_result(dirb_output)
            dirb_process.kill()  # Ensure Dirb process is terminated after capturing output
        except Exception as e:
            self.display_scan_result(f"Dirb Scan Error: {e}")

# Run the application
if __name__ == "__main__":
    app = SecurityScannerApp()
    app.mainloop()

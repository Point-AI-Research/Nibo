#!/usr/bin/python3
import subprocess
import argparse
import re
import json
import os
import sys
import time
from datetime import datetime
from threading import Thread
import random
import signal

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class Spinner:
    def __init__(self):
        self.spinning = False
        self.spinner_chars = '⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
        self.spinner_thread = None

    def spinner_task(self):
        i = 0
        while self.spinning:
            sys.stdout.write(f"\r{Colors.CYAN}{self.spinner_chars[i]}{Colors.ENDC} ")
            sys.stdout.flush()
            time.sleep(0.1)
            i = (i + 1) % len(self.spinner_chars)

    def start(self):
        self.spinning = True
        self.spinner_thread = Thread(target=self.spinner_task)
        self.spinner_thread.start()

    def stop(self):
        self.spinning = False
        if self.spinner_thread:
            self.spinner_thread.join()
        sys.stdout.write('\r')
        sys.stdout.flush()

class NetworkScanner:
    def __init__(self, target_ip, aggressive=False, output_format="all"):
        self.target_ip = target_ip
        self.aggressive = aggressive
        self.output_format = output_format
        self.results_dir = "scan_results"
        self.create_results_dir()
        self.spinner = Spinner()
        signal.signal(signal.SIGINT, self.signal_handler)
        
    def signal_handler(self, signum, frame):
        print(f"\n{Colors.FAIL}[!] Scan interrupted by user. Cleaning up...{Colors.ENDC}")
        self.spinner.stop()
        sys.exit(1)

    def print_banner(self):
        banner = f"""
{Colors.CYAN}
███╗   ██╗███████╗████████╗ ██████╗ ██████╗ ███████╗
████╗  ██║██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗██╔════╝
██╔██╗ ██║█████╗     ██║   ██║   ██║██████╔╝███████╗
██║╚██╗██║██╔══╝     ██║   ██║   ██║██╔═══╝ ╚════██║
██║ ╚████║███████╗   ██║   ╚██████╔╝██║     ███████║
╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝     ╚══════╝
                                                     
{Colors.GREEN}[+] Advanced Network Scanner and Enumeration Tool{Colors.ENDC}
{Colors.BLUE}[+] Target: {self.target_ip}{Colors.ENDC}
{Colors.WARNING}[+] Mode: {'Aggressive' if self.aggressive else 'Standard'}{Colors.ENDC}
{Colors.BOLD}════════════════════════════════════════════════════{Colors.ENDC}
"""
        print(banner)

    def create_results_dir(self):
        if not os.path.exists(self.results_dir):
            os.makedirs(self.results_dir)
            
    def validate_ip(self):
        pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        if not pattern.match(self.target_ip):
            raise ValueError(f"{Colors.FAIL}Invalid IP address format{Colors.ENDC}")
        octets = self.target_ip.split('.')
        if not all(0 <= int(octet) <= 255 for octet in octets):
            raise ValueError(f"{Colors.FAIL}IP address octets must be between 0 and 255{Colors.ENDC}")

    def print_status(self, message, status="info"):
        color = {
            "info": Colors.BLUE,
            "success": Colors.GREEN,
            "warning": Colors.WARNING,
            "error": Colors.FAIL
        }.get(status, Colors.ENDC)
        
        print(f"{color}[+] {message}{Colors.ENDC}")

    def run_command(self, command):
        try:
            self.spinner.start()
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
                text=True
            )
            output, error = process.communicate()
            self.spinner.stop()
            return output if not error else f"Error: {error}"
        except Exception as e:
            self.spinner.stop()
            return f"Failed to run command: {str(e)}"

    def nmap_basic_scan(self):
        self.print_status("Running basic Nmap scan...")
        command = f"nmap -sV -sC {self.target_ip}"
        return self.run_command(command)

    def nmap_full_scan(self):
        self.print_status("Running full port Nmap scan...")
        command = f"nmap -p- -sV {'-A' if self.aggressive else ''} {self.target_ip}"
        return self.run_command(command)

    def nmap_udp_scan(self):
        self.print_status("Running UDP scan...")
        command = f"nmap -sU --top-ports {'1000' if self.aggressive else '100'} {self.target_ip}"
        return self.run_command(command)

    def check_vulnerabilities(self):
        self.print_status("Running vulnerability scan...")
        command = f"nmap -sV --script vuln {self.target_ip}"
        return self.run_command(command)

    def os_detection(self):
        self.print_status("Attempting OS detection...")
        command = f"nmap -O --osscan-guess {self.target_ip}"
        return self.run_command(command)

    def check_waf(self):
        self.print_status("Checking for WAF...", "info")
        command = f"wafw00f http://{self.target_ip} 2>/dev/null"
        return self.run_command(command)

    def check_ssl(self):
        self.print_status("Checking SSL/TLS configuration...")
        command = f"sslscan --no-colour {self.target_ip} 2>/dev/null"
        return self.run_command(command)

    def service_enumeration(self):
        self.print_status("Running service enumeration...")
        results = {}
        
        # Check for common web ports
        web_ports = [80, 443, 8080, 8443]
        for port in web_ports:
            command = f"curl -IL --connect-timeout 5 http{'s' if port == 443 or port == 8443 else ''}://{self.target_ip}:{port}"
            result = self.run_command(command)
            if "HTTP/" in result:
                results[f"web_port_{port}"] = result

        # Check for SSH
        ssh_result = self.run_command(f"nc -zv -w3 {self.target_ip} 22")
        if "succeeded" in ssh_result.lower():
            results["ssh"] = ssh_result

        # Additional service checks if aggressive mode is enabled
        if self.aggressive:
            # SMB enumeration
            smb_result = self.run_command(f"enum4linux {self.target_ip}")
            results["smb"] = smb_result

            # SNMP enumeration
            snmp_result = self.run_command(f"snmpwalk -v1 -c public {self.target_ip}")
            results["snmp"] = snmp_result

        return results

    def save_results(self, scan_results):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save as JSON
        json_filename = f"{self.results_dir}/scan_{self.target_ip}_{timestamp}.json"
        with open(json_filename, 'w') as f:
            json.dump(scan_results, f, indent=4)

        # Save as text report
        report_filename = f"{self.results_dir}/report_{self.target_ip}_{timestamp}.txt"
        with open(report_filename, 'w') as f:
            f.write(f"Network Scan Report for {self.target_ip}\n")
            f.write(f"Generated on: {scan_results['timestamp']}\n")
            f.write("=" * 50 + "\n\n")
            
            for scan_type, result in scan_results['scans'].items():
                f.write(f"\n=== {scan_type.upper()} ===\n")
                f.write(str(result))
                f.write("\n" + "=" * 50 + "\n")

        self.print_status(f"Results saved to {json_filename} and {report_filename}", "success")

    def run_all_scans(self):
        try:
            self.validate_ip()
            self.print_banner()
            
            results = {
                "target_ip": self.target_ip,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "scan_mode": "aggressive" if self.aggressive else "standard",
                "scans": {
                    "nmap_basic": self.nmap_basic_scan(),
                    "nmap_full": self.nmap_full_scan(),
                    "nmap_udp": self.nmap_udp_scan(),
                    "os_detection": self.os_detection(),
                    "vulnerabilities": self.check_vulnerabilities(),
                    "service_enumeration": self.service_enumeration(),
                }
            }

            # Additional aggressive mode scans
            if self.aggressive:
                results["scans"].update({
                    "waf_detection": self.check_waf(),
                    "ssl_scan": self.check_ssl()
                })

            self.save_results(results)
            self.print_summary(results)
            return results

        except Exception as e:
            self.print_status(f"Error during scan: {str(e)}", "error")
            return None

    def print_summary(self, results):
        print(f"\n{Colors.GREEN}[+] Scan Complete! Summary of findings:{Colors.ENDC}")
        print(f"{Colors.BLUE}Target:{Colors.ENDC} {results['target_ip']}")
        print(f"{Colors.BLUE}Scan Time:{Colors.ENDC} {results['timestamp']}")
        print(f"{Colors.BLUE}Mode:{Colors.ENDC} {results['scan_mode']}")
        print(f"\n{Colors.WARNING}Key Findings:{Colors.ENDC}")
        
        # Extract and display important findings
        for scan_type, result in results['scans'].items():
            if result and "Error" not in result:
                print(f"{Colors.CYAN}✓ {scan_type.replace('_', ' ').title()}{Colors.ENDC}")

def main():
    parser = argparse.ArgumentParser(
        description=f"{Colors.CYAN}Advanced Network Scanner and Enumeration Tool{Colors.ENDC}",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("target_ip", help="Target IP address to scan")
    parser.add_argument("-a", "--aggressive", action="store_true", help="Enable aggressive scanning")
    parser.add_argument("-o", "--output", choices=["json", "text", "all"], default="all",
                      help="Output format (default: all)")
    args = parser.parse_args()

    scanner = NetworkScanner(args.target_ip, args.aggressive, args.output)
    scanner.run_all_scans()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.FAIL}[!] Scan terminated by user{Colors.ENDC}")
        sys.exit(1)

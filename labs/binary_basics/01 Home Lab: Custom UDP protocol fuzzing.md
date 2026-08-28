
## Custom UDP protocol and binary analysis

My goal was to learn more about buffer overflow and binary analysis outside of online platforms. Using generative AI to help create some different pieces helped me see how this vulnerable program looked from multiple angles while learning a little more about Wireshark, C code, and various binary analysis tools. This little experiment is simple to set-up and helped solidify calculating the memory offset. 

**Objectives**

Better understand:
+ custom protocol capture setup using .lua
+ registering a .lua plugin in Wireshark
+ creating a C daemon using the custom protocol
+ testing for a vulnerability to buffer overflow


**Tools / Environment**
+ Wireshark
+ gdb
+ pwntools
+ 2 Linux environments


**Building / Setup**
+ Create daemon.c file

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 9999
#define MAGIC 0xDEAD
#define MAX_RAW 2048

#pragma pack(push, 1)
typedef struct {
    uint16_t magic;
    uint8_t  msg_type;
    uint8_t  flags;
    uint16_t length;
    uint16_t seq_id;
} proto_header_t;
#pragma pack(pop)

void process_packet(const uint8_t *data, size_t size) {
    char local_buffer[64]; // Vulnerable stack buffer
    const proto_header_t *hdr = (const proto_header_t *)data;

    uint16_t magic = ntohs(hdr->magic);
    uint16_t payload_len = ntohs(hdr->length);

    if (magic != MAGIC) {
        printf("[-] Invalid Magic: 0x%04X\n", magic);
        return;
    }

    printf("[+] Packet Received | Type: 0x%02X | Flags: 0x%02X | Length: %u | Seq: %u\n",
           hdr->msg_type, hdr->flags, payload_len, ntohs(hdr->seq_id));

    // VULNERABILITY: Blindly copies untrusted payload_len into a 64-byte stack buffer
    if (size >= sizeof(proto_header_t) + payload_len) {
        const uint8_t *payload = data + sizeof(proto_header_t);
        memcpy(local_buffer, payload, payload_len);
        printf("[+] Processed %u bytes of payload successfully.\n", payload_len);
    }
}

int main() {
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    uint8_t buffer[MAX_RAW];
    socklen_t addr_len = sizeof(client_addr);

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("[*] Protocol Daemon listening on UDP port %d...\n", PORT);

    while (1) {
        ssize_t n = recvfrom(sockfd, buffer, sizeof(buffer) - 1, 0,
                             (struct sockaddr *)&client_addr, &addr_len);
        if (n >= (ssize_t)sizeof(proto_header_t)) {
            process_packet(buffer, n);
        }
    }

    close(sockfd);
    return 0;
}
```

+ compile the daemon with no stack protections so we can easily produce a buffer overflow
```bash
gcc -fno-stack-protector -z execstack -no-pie -g daemon.c -o daemon
```

+ create .lua plugin for wireshark with custom protocol
+ 
Note: not necessary to have a custom protocol, but this was something I wanted to see in action.


```lua
-- Declare protocol
local custom_proto = Proto("customproto", "Custom IoT Sensor Protocol")

-- Protocol fields
local f_magic   = ProtoField.uint16("customproto.magic",   "Magic Bytes",  base.HEX)
local f_type    = ProtoField.uint8( "customproto.type",    "Message Type", base.HEX)
local f_flags   = ProtoField.uint8( "customproto.flags",   "Flags",        base.HEX)
local f_length  = ProtoField.uint16("customproto.length",  "Payload Size", base.DEC)
local f_seq     = ProtoField.uint16("customproto.seq",     "Sequence ID",  base.DEC)
local f_payload = ProtoField.bytes( "customproto.payload", "Payload Data")

custom_proto.fields = { f_magic, f_type, f_flags, f_length, f_seq, f_payload }

-- Dissector function
function custom_proto.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length < 8 then return end

    -- Check Magic Header (0xDEAD)
    local magic_val = buffer(0, 2):uint()
    if magic_val ~= 0xDEAD then return end

    pinfo.cols.protocol = "CUSTOM-PROTO"

    -- Subtree in Packet Details
    local subtree = tree:add(custom_proto, buffer(), "Custom Protocol Data")
    subtree:add(f_magic,   buffer(0, 2))
    subtree:add(f_type,    buffer(2, 1))
    subtree:add(f_flags,   buffer(3, 1))
    subtree:add(f_length,  buffer(4, 2))
    subtree:add(f_seq,     buffer(6, 2))

    local payload_size = buffer(4, 2):uint()
    pinfo.cols.info = string.format("Type: 0x%02X, Seq: %d, Len: %d", 
                                    buffer(2, 1):uint(), 
                                    buffer(6, 2):uint(), 
                                    payload_size)

    -- Highlight remaining payload
    if length > 8 then
        subtree:add(f_payload, buffer(8, length - 8))
    end
end

-- Bind dissector to UDP port 9999
local udp_port = DissectorTable.get("udp.port")
udp_port:add(9999, custom_proto)
```


+ load .lua plugin into Wireshark by saving the file in the specific folder for your OS (https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html)
+ plugin should be visible in About menu, Plugins tab:
<img width="745" height="200" alt="image" src="https://github.com/user-attachments/assets/07f1bf0a-24e2-48e3-9848-1a1c82bac3b7" />



**Execution / Logic**

First, start the daemon program on a secondary machine/VM; in my case I had it running on a Kali Linux VM. 

+ make sure Wireshark is in capture mode
+ test the plugin with a simple Python script from main machine/VM terminal

```python
import socket
import struct

TARGET_IP = "127.0.0.1" # YOUR IP
TARGET_PORT = 9999

# Header: Magic(0xDEAD), Type(0x01), Flags(0x00), Length(12), Seq(1001)
header = struct.pack(">HBBHH", 0xDEAD, 0x01, 0x00, 12, 1001)
payload = b"Hello Daemon"

packet = header + payload

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(packet, (TARGET_IP, TARGET_PORT))
print(f"Sent {len(packet)} bytes to {TARGET_IP}:{TARGET_PORT}")
```

I did a quick ping to make sure the VM was reachable. After running the Python test script, you should see something like this in Wireshark:
<img width="1105" height="156" alt="image" src="https://github.com/user-attachments/assets/770f34cf-5ad1-4b85-b2f7-300297570528" />


The daemon will look like this:
<img width="571" height="250" alt="image" src="https://github.com/user-attachments/assets/2be55029-1646-4dd1-9b1d-b68c5444758b" />


Next, I'll run the daemon using gdb and test again:
<img width="878" height="741" alt="image" src="https://github.com/user-attachments/assets/4b54ac3a-d079-41af-89ab-2e371c832e9a" />


Wireshark captures the following:
<img width="1463" height="525" alt="image" src="https://github.com/user-attachments/assets/e85d7f2d-68eb-4588-98fb-3a3b82cf756d" />



Next, I create a Python script to fuzz the daemon by sending payloads of different sizes until the program crashes. In doing so, we can calculate the memory offset, which is the point where we need to insert our code if we were attempting to exploit the program. The Python script below simply increments the payload up to a maximum # of bytes as a first attempt:

```python
import socket
import struct
import time

TARGET_IP = "192.168.XX.XX"  # Replace IP
TARGET_PORT = 9999

# Fixed protocol fields for this case because of the custom protocol 
MAGIC = 0xDEAD
MSG_TYPE = 0x01
FLAGS = 0x00
SEQ_ID = 1

# Start with a safe payload size and increment
payload_len = 32
step = 16
max_len = 512

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(1.0)

print(f"[*] Starting UDP fuzzer against {TARGET_IP}:{TARGET_PORT}")

while payload_len <= max_len:
    # 1. Generate payload of varying size
    payload = b"A" * payload_len
    
    # 2. Pack the 8-byte binary header matching C struct:
    # > = Big-Endian, H = uint16 (2B), B = uint8 (1B)
    header = struct.pack(">HBBHH", MAGIC, MSG_TYPE, FLAGS, payload_len, SEQ_ID)
    packet = header + payload

    print(f"[+] Sending {len(packet)} bytes (Header: 8, Payload: {payload_len})...")
    sock.sendto(packet, (TARGET_IP, TARGET_PORT))
    
    SEQ_ID += 1
    payload_len += step
    time.sleep(0.2)

print("[*] Fuzzing sequence completed.")

```


Next, I learned about pwntools and creating a De Bruijn cyclic pattern (Metasploit also has this ability or you can create a manual function). A cyclic pattern will allow you to find the offset much quicker than testing payloads of different lengths like the above. Replace the incrementing payload with 'pattern = cyclic(2000)', for example, while adding an import: 'from pwn import cyclic'. The gdb output looks like this:

<img width="927" height="308" alt="image" src="https://github.com/user-attachments/assets/c33d5366-1f53-46da-b096-7dc5cc172538" />


For fun, here is the manual cyclic pattern version:

```python
def de_bruijn_cyclic(length=2100):
    """Generates a standard 4-byte De Bruijn cyclic pattern (Aa0Aa1Aa2...)."""
    pattern = bytearray()
    for upper in range(ord('A'), ord('Z') + 1):
        for lower in range(ord('a'), ord('z') + 1):
            for num in range(ord('0'), ord('9') + 1):
                for sub in range(ord('a'), ord('z') + 1):
                    if len(pattern) >= length:
                        return bytes(pattern[:length])
                    pattern.extend([upper, lower, num, sub])
    return bytes(pattern[:length])

pattern = de_bruijn_cyclic(2100)
```


Querying gdb for the contents of RSP using 'x/gx $rsp' gives an output of 0x6261616362616162. This is a portion of the cyclic pattern that was sent earlier. Next we can use pwntools to find the exact offset: 

<img width="417" height="40" alt="image" src="https://github.com/user-attachments/assets/fb3d305f-15cf-4253-b0f4-0564e124e9d4" />




**Verification / Findings**

In this instance, I did not create shell code for an exploit or attempt anything further. I mainly wanted to see how this custom protocol looked in Wireshark while running a local daemon. The different scripts attempted for fuzzing helped me understand how those payloads landed in RSP when the program crashed, how the payloads display in Wireshark (and therefore ingested by any packet sniffing defense tools), and pwntools aided calculating the offset much faster. Beyond this experiment, I moved on to other labs to find out ways to get the right memory address to land the payload, packing the payload, and executing shellcode on both Windows and Linux binaries. 


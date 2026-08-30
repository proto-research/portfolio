
### THM Gatekeeper Room

This room is in the Offensive Security path and related to both buffer overflow and privilege escalation on a Windows machine. Here is my quick
rundown of steps to get in. 


Port enumeration:
<br>
<img width="799" height="342" alt="image" src="https://github.com/user-attachments/assets/a157afbc-53d9-41a8-bc1f-da4de2e12703" />


NSSE script for SMB shares:
<br>
<img width="800" height="817" alt="image" src="https://github.com/user-attachments/assets/a0cc81d8-5751-44fa-964f-066036133c86" />


Check what is available in shares:
<br>
<img width="800" height="402" alt="image" src="https://github.com/user-attachments/assets/f7d551b6-8d84-4257-944a-91cf6f6df4b7" />


Use 'ropper' to see if there is a quick win for instruction:
<br>
<img width="572" height="159" alt="image" src="https://github.com/user-attachments/assets/7a703e64-02e9-44a4-8672-7ecb44899e40" />


Use netcat to connect to it / send cyclic:
<br>
<img width="1345" height="310" alt="image" src="https://github.com/user-attachments/assets/3c271d9d-6b1d-46ce-8bef-302912d69759" />


Response from running app:
<br>
<img width="379" height="199" alt="image" src="https://github.com/user-attachments/assets/0bae464c-3839-40a5-9324-fc89a32f4e97" />

Use x32dbg to check EIP:
<br>
<img width="1186" height="646" alt="image" src="https://github.com/user-attachments/assets/ff14483f-c936-4e07-9dc6-96708e9b5987" />


Use pwntools to find offset from cyclic pattern returned in EIP:
<br>
<img width="293" height="80" alt="image" src="https://github.com/user-attachments/assets/0cee421a-f808-4210-a9ff-9f5aab5648ec" />
<br>
<br>

Tried to validate offset was correct using a script and that worked with "BBBB" showing in EIP:
<br>
<img width="551" height="781" alt="image" src="https://github.com/user-attachments/assets/a3c034b3-279e-4220-b092-1adc74fa71b2" />

<br>
<br>

However, when I got to sending the exploit script, it did not work even though all appeared the same as other challenge I had run through.
Thinking through possible options, it appeared as though the program
was exiting prior to sending the payload from the script. It occurred to me that the output of the file may hold a clue:
<br>
<br>
<img width="379" height="199" alt="image" src="https://github.com/user-attachments/assets/00677e21-8c36-4324-ab47-defa117a7de7" />
<br>
<br>
It states it's existing the thread, and this behavior was also mirrored inside x32dbg. I did some searching on this and there is an option in
msfvenom to change EXITFUNC=thread whereas the default is to exit process. Changing my code using this output did not work still, but was good to know
and still could be relevant. 
<br>
<br>

Second, I had read about "bad bytes" related to fuzzing, so I decided to check this too running the super basic script find_bad_char.py to run through
all the characters which showed 0x0A as a bad byte:
<br>
<br>
<img width="1008" height="789" alt="image" src="https://github.com/user-attachments/assets/72156d2f-81a9-4a7e-92c9-ebc870ac5b9e" />
<br>
<br>

After adjusting the code once again excluding these bad bytes, I was able to get into the user 'natbat':
<br>
<img width="656" height="134" alt="image" src="https://github.com/user-attachments/assets/fb4b151c-be17-400f-a0d1-ed4af13dfff5" />


<br>
<br>

Tried various things:
+ privileges - nothing
+ tried eternal blue and some other metasploit fun
+ tried uploading PowerUp.ps1, but couldn’t run
+ tried a few commands I found in places online
<br>
<br>
Finally looked it up, and got a hint for browser credentials in Firefox. 

C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles>
go to appdata/roaming/mozilla/firefox/profiles and go into default-profile directory. Two files to download:
key4.db
logins.json

I needed to find a Windows compatible netcat binary to upload to the user (which lives in Kali btw). After that, 
I was able to exfil the files to my attacker VM to proceed with cracking. 
Using a lovely script from the interwebs (so safe!) - I was able to get the credentials out:
<br>
<img width="629" height="84" alt="image" src="https://github.com/user-attachments/assets/25483c4d-74e0-4f2b-8927-f82bcc888e37" />

<br>
<br>

From there, still needed to use those credentials to get in, so used impacket + psexec:
<br>
<img width="809" height="256" alt="image" src="https://github.com/user-attachments/assets/9dc9494d-13e7-4542-8f20-9cb29a19fc93" />

<br>
<br>

Which quickly gave me root:
<br>
<img width="458" height="245" alt="image" src="https://github.com/user-attachments/assets/574c4427-57e5-4555-921d-be2b60c3bcad" />


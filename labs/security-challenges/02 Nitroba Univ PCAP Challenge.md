### Nitroba University PCAP Challenge

I found this challenge online while trying to find something to hone pcap investigation skills. It provided a pcap file and list of students
in the professor's class. 
<br>


**Problem**

A university professor received threatening email from a student. The professor notified the IT department of the email and 
provided the email headers. The IT department traced the headers to one particular dorm room with three female occupants; they 
subsequently set up a packet sniffer to determine who is sending these emails. The professor received another email after 
the sniffer was in place.

<br>

**Objective**

Review the packet capture file to determine who sent the email based on the provided list of students from the professor’s class. 
Must determine who specifically sent the email and identify the TCP flow that includes the hostile message. 

<br>
<br>

**Note**

I came to the wrong conclusion at first because I went to fast and relied solely on plain text searching. 
I found a person named Amy in the packet capture and the timing seemed to line up with the visits to the 
“willselfdestruct.com” website, but she appeared right after the malicious emails were sent with the same 
IP address, which is what threw me the first time.
This was a good lesson as it highlights not stopping at the first thing and taking your time or giving it
a second look to make sure nothing else sticks out to validate your hypothesis is correct.
<br>
<br>

**Second look timeline**

Isolating the user agent in Wireshark helped immensely, which differed from other users and was attached to all the web traffic that sent
these two malicious emails. 

Timeline  | User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)
+ frame 72122 | 1:57 PM: first frame with Windows NT user agent
+ frame 74059 | 1:58 PM: search “sending anonymous email”
+ frame 74334 | 1:58 PM: search “I want to harrass my teacher”
+ frame 74920 | 1:58 PM: search “can I go to jail for harassing my teacher”
+ frame 77508 | 2:00 PM: google calendar auth with jcoach@gmail.com<<-----------actual sender
+ frame 79780 | 2:01 PM: search “send anonymous email”
+ frame 79797 | 2:01 PM: clicked URL for “sendanonymousemail.net”
+ frame 80614 | 2:02 PM: sent malicious message from ‘sendanonymousemail.net’ 
+ frame 83601 | 2:04 PM: sent another message via ‘willselfdestruct.com’
+ frame 84201 | 2:04 PM: last User Agent with Windows NT showing

Frames around this activity showed same IP address, but the user agent was: 
User-Agent: Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en-US; rv:1.8.1.16) Gecko/20080702 Firefox/2.0.0.16
which I tie now to the Amy person, who is also in the teacher's class. She was possibly
in the same space while he was doing it though, so that is something to note because her
browser was active before and after the message were send on the same network.
<br>
<br>

**Workflow adjusted to something like:**
+ free text search on email or whatever key words first since information given with challenge stated the teacher's email address; 
this can be used to find the messages in the pcap file as a starting place
+ isolate details from malicious messages (user agent, time stamps, tcp stream numbers)
+ try to follow from first appearance to last through isolating TCP and HTTP conversations, filtering out noise like ad server IPs, etc.
<br>
<br>
Screenshot of user indicator
<br>

<img width="1189" height="584" alt="image" src="https://github.com/user-attachments/assets/643083d3-96fe-4406-b0cf-56ea1898b444" />

<br>
<br>

Screenshot of malicious message 1
<br>
<img width="1541" height="727" alt="image" src="https://github.com/user-attachments/assets/7722c205-a1d6-4172-a040-f597ad6455c1" />


<br>
<br>

Screenshot of malicious message 2
<br>
<img width="1305" height="845" alt="image" src="https://github.com/user-attachments/assets/80e11728-1cb1-45ed-bd68-5684f45d677e" />




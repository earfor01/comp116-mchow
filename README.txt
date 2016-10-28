README 

Libby Arford 
Lab 4 Scapy 

reconstruct_image.py
alarm.py
*used tokens 


Identify what aspects of the work have been correctly implemented and what have not:

Reconstruct_image.py works to reconstruct an image encoded in
the payload and identify what type of image it is. Alarm.py 
detects FIN, NULL and XMAS scans as well as passwords 
sent in the clear, though it may not pick up on all 
of these incidents and does over-trigger. I was unable to 
test is masscan pr shellshocked was actually detected, 
but the alarm did trigger at mention of phpMyAdmin. I built 
a packet that passed numbers fitting the specs given 
for credit cards, and the alarm triggered, although 
I’m unsure it would do so for all incidents of that nature. 

Identify anyone with whom you have collaborated or discussed the assignment

I did not collaborate with anyone, but as I have never used python before I 
 spent a significant amount of time looking through  the Python Library and 
through other online reference sources (particularly SANS information and 
stack overflow and the scary documentation file) 

Say approximately how many hours you have spent completing the assignment?

Probably too long. I spent at least 48 hours on this 

Are the heuristics used in this assignment to determine incidents "even that good”?

No, I wouldn’t market this tool. Primarily, although I learned ALOT about how the 
detection works, there are so many methods of moving information, not to mention 
encryption, that the tools implemented in this would probably only catch a fraction 
of incidents. For the NULL, FIN I utilised a counter, as they are naturally 
occurring actions “in the wild” and are only notable if they appear in quantities 
out of the ordinary. I looked at pcaps of these incidents, but the ratios and 
numbers i used were relatively arbitrary, and there could definitely be a more 
refined method of flagging these actions. The password detection will trigger for any 
content that fits the right protocol and contains “user” or “pass,” which could 
be more than the actual user names and passwords sent in the clear. 

If you have spare time in the future, what would you add to the program or do
differently with regards to detecting incidents?

Python is definitely the highest level linage I’ve coded it, and I found myself
down a rabbit hole, that in introspect, seems unnecessary. I think I could 
have converted all my filters to sniff filters, instead of writing the actual 
functions myself. Additionally, I would like to further research the common ways
info is send in the clear, so I could add additional focused situations. 
I chose to specify certain ways the data would be sent in an effort to avoid 
being flooded in false alarms. For password detection I think this is a good 
trade off (missing some, but not having a lot of irrelevant results), but 
I could certainly create more cases to check. For the scans, assuming didn’t change 
the entire structure of my code, it would be interesting to research exactly how 
many packets with FIN flags does an average FIN scan send, or the ratio of SYN to 
SYN-ACK responses in a SYN scan. 







Rob Lasell
Comp 116
Ming Chow
Assignment 1: Packet Sleuth
================================

Set 1:

1. There were 1503 packets in this set.

2. File Transfer Protocol (FTP)

3. FTP transmits information in clear text. For example, I can see this user's username and password.

4. A secure protocol like FTPS or HTTPS

5. 67.23.79.113

6. Username: ihackpineapples
   Password: rockyou1

7. 4 files

8. 	BjN-O1hCAAAZbiq.jpg
	BvgT9p2IQAEEoHu.jpg
	BvzjaN-IQAA3XG7.jpg
	smash.txt

--------------------------------

Set 2:

10. 77882 packets

11. 8 pairs

12. I used ettercap to find the first (legit) pair, then dsniff to find the remaining 7.

13. The pairs all seem to have used TCP. The legitimate username/password pair, chris@digitalinterlude.com, used the IP address 10.104.15.184, the domain digitalinterlude.com, and port 33240. I am not sure which domain is associated with the other 7, which all use the username cisco, but their IP address is 10.156.15.241 and their port is 13256.

14. Only one pair, with the username chris@digitalinterlude.com, was legitimate and granted access.

15. Filtering the pcap file by the IP addresses used by the username/password pairs via wireshark allows you to follow the TCP stream and determine the success or failure of the attempts.

16. Use some kind of secure protocol... jeez.

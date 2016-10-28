#!/usr/bin/python

from scapy.all import *
import sys, os
import re
import getopt

def main(argv):
    interface = "eth0"
    pcapfile = None
    valid = 0
    if len(argv) == 0:
        valid = 1;
    try:
        opts, args = getopt.getopt(argv, "hi:r:")
    except getopt.GetoptError:
        usage()
        sys.exit(2)
    for opt, arg in opts:
        valid = 1
        if opt in ("-h"):
            usage()
            sys.exit() 
        elif opt in ("-i"):
            interface = arg
        elif opt in ("-r"):
            pcapfile = rdpcap(arg)
        else:
            usage()
            sys.exit()

    if valid != 1:
        usage()
        sys.exit()
    if pcapfile != None:
         runpcap(pcapfile)
    else:
         runface(interface)
  
    return  


def usage():
    print "usage: alarm.py [-h] [-i INTERFACE] [-r PCAPFILE]"
    print "A network sniffer that identifies basic vulnerabilities"
    print "optional arguments:"
    print "-h, --help    show this help message and exit"
    print "-i INTERFACE  Network interface to sniff on"
    print "-r PCAPFILE   A PCAP file to read"
    return

def runface(interface):
    try:
        sniff(iface=interface, prn=runpcap)
    except Exception:
        print "Failed to initiate sniffing"
    sys.exit(1)


def runpcap(p):
    # TCP flags
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80

    # alert info
    alertnum = 0
    alert = ''
    sourceip = ''
    protocol = ''
    payload = ''

    nullcount = 0
    fincount = 0
    syncount = 0
    synackcount = 0
    niptrack = ''
    fiptrack = ''
    niktoagent = "USERAGENT=Mozilla/5.00 (Nikto/@VERSION)"
    shellshockcode = "() { :;};"

    for x in p:
        # source IP
        if x.haslayer(IP):     
            sourceip = x.getlayer(IP).src
        # NULL scan
        if (x.haslayer(TCP)) and (x[TCP].seq == 0) and (x[TCP].flags == 0):
            if sourceip == niptrack:
                nullcount = nullcount + 1
                if nullcount > 100:
                    nullcount = 0
                    alertnum = alertnum + 1
                    alarm(alertnum, "NULL scan", sourceip, "TCP", str(x.load))
            else:
                niptrack = x[IP].src
        # FIN scan
        elif (x.haslayer(TCP)) and (x[TCP].flags == FIN):
            if sourceip == fiptrack:
                fincount = fincount + 1
                if fincount > 100:
                    fincount = 0
                    alertnum = alertnum + 1
                    alarm(alertnum, "FIN scan", sourceip, "TCP", str(x.load))
            else:
                fiptrack = x[IP].src
        # XMAS scan
        elif (x.haslayer(TCP)) and (x[TCP].flags == (FIN + PSH + URG)):
            alertnum = alertnum + 1
            alarm(alertnum, "XMAS scan", sourceip, "TCP", str(x.load))
        # Masscan scan
        elif (x.haslayer(TCP)) and (x[TCP].flags == SYN) and (x[TCP].options == "{}"):
            alertnum = alertnum + 1
            alarm(alertnum, "Possible Masscan scan", sourceip, "TCP", str(x.load))
        # Checking on HTTP
        elif x.haslayer(TCP) and (x[TCP].sport == 80 or x[TCP].dport == 80):
            layer = str(x)
            #Nikto scan
            if layer.find(niktoagent) != -1:  
                alertnum = alertnum + 1
                alarm(alertnum, "Nikto scan", sourceip, "HTTP", str(x.load))
            #Shellshock used
            elif layer.find(shellshockcode) != -1:  
                alertnum = alertnum + 1
                alarm(alertnum, "Someone scanning for Shellshock vulnerability", sourceip, "HTTP", str(x.load))
        elif x.haslayer(TCP):
            #SYN-ACK scan   
            if x[TCP].flags == SYN:
                syncount = syncount + 1
            if x[TCP].flags == (SYN + ACK):
                synackcount = synackcount + 1
            if (syncount - synackcount) > 100:
                    syncount = 0
                    synackcount = 0
                    alertnum = alertnum + 1
                    alarm(alertnum, "SYN ACK scan", sourceip, "TCP", str(x.load))
            packet = str(x[TCP].payload)
            # phpMyAdmin detected
            if (x[TCP].sport == 3306) and (packet.find("phpMyAdmin") != -1):
                alertnum = alertnum + 1
                alarm(alertnum, "Someone looking for phpMyAdmin stuff", sourceip, "TCP", str(x.load))
            # Passwords/Usernames being sent (sorted by method)
            elif "user" in packet or "pass" in packet:
                # By email
                if (x[TCP].sport in {100, 143, 25}) or (x[TCP].dport in {100, 143, 25}):
                    alertnum = alertnum + 1
                    alarm(alertnum, "Email username/password sent in the clear", sourceip, "TCP", packet)
                # By HTTP
                elif (x[TCP].sport == 80) or (x[TCP].dport == 80):
                    alertnum = alertnum + 1
                    alarm(alertnum, "Username/password sent in the clear", sourceip, "HTTP", packet)
                # By FTP
                elif (x.haslayer(Raw)) and (x[TCP].sport == 21) or (x[TCP].dport == 21):
                    info = str(x[Raw].load)
                    if "user" in info or "pass" in info:
                        alertnum = alertnum + 1
                        alarm(alertnum, "Username/password sent in the clear", sourceip, "FTP", info)
        # Search for credit card info
        elif x.haslayer(Raw):
            info = str(x[Raw].load)
            amex = re.findall('3[0-9]{14}', info)
            disc = re.findall('6011[0-9]{12}', info)
            mcard = re.findall('5[0-9]{15}', info)
            visa = re.findall('4[0-9]{15}', info)
            if visa:
                alertnum = alertnum + 1
                alarm(alertnum, "Visa info sent in the clear" , sourceip, "Raw", visa)
            elif disc:
                alertnum = alertnum + 1
                alarm(alertnum, "Discovery info sent in the clear" , sourceip, "Raw", disc)
            elif mcard:
                alertnum = alertnum + 1
                alarm(alertnum, "Mastercard info sent in the clear" , sourceip, "Raw", mcard)
            elif amex:
                alertnum = alertnum + 1
                alarm(alertnum, "AmericanExpress info sent in the clear" , sourceip, "Raw", amex)



def alarm(num, alarmtype, ip, col, load):
     print "ALERT #%d: %s is detected from %s (%s) (%s)!" % (num, alarmtype, ip, col, load)
     return


if __name__ == "__main__":
    main(sys.argv[1:])
#!/usr/bin/python

from scapy.all import *
import imghdr
import base64
import os, sys

p = rdpcap("picture.pcap")
pic = ''

for x in p:
    pic = pic + x.load

pic_decoded = base64.b64decode(pic)

fileimage = 'image.png'
with open(fileimage, 'wb') as f:
    f.write(pic_decoded)

image_name = 'output.' + imghdr.what('image.png')
os.rename("image.png", image_name)
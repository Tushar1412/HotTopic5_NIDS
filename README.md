# HotTopic5_NIDS

This is a intrusion detection system created by Team HotTopic5.

# To Install
```sh
chmod u+x setup.sh Run.py && sudo ./setup.sh
```
myrules.txt could be your own file of rules

# To Run 
```sh
sudo python3 Run.py myrules.txt
```
      # OR
      
```sh
sudo python3 Run.py myrules.txt >> (output file).txt
```
```sh
#Rules format

alert udp any any -> any any (tos:_;msg:"";flags:_;offset:_;content:_;seq:_;ack:_;)

```

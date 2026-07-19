README

# spdm-i2c-plugin


## Description


SPDM-i2c.lua is wireshark plugin to dissect SPDM protocol. (spdm over mctp over smbus)


## Installation



### Download spdm plugin for wireshark

git clone https://github.com/travelant/spdm-i2c-plugin.git



### Install plugin

Open wireshark menu， Help==》 about wireshark ==》 folders ==》 global lua plugins， you can find lua plugin path. In my case the path is "D:\\Users\\<userid>\\Downloads\\WiresharkPortable64\\App\\Wireshark\\plugins"

Copy SPDM-i2c.lua into that lua plugin path.

Restart wireshark if wireshark is runnig.

Check wireshark menu, Help==>about wireshark ==> plugins, you can find SPDM-i2c.lua is list, which means SPDM-i2c.lua is installed.



### Usage

Have wireshark open a tracing file which is captured by tcpdump. Filter is spdm.

if the package has spdm protocal, you can find that spdm is also dissected.



## Examples

Examples folder contains spdm-dissector.pcap, which is real data for people to exam this function. User can use wireshark with spdm plugin installed to open this spdm-dissector.pcap.

Examples folder contains wireshark-spdm-screenshot.png, which is screenshot of wireshark with spdm plugin installed to show dissection of spdm-dissector.pcap.

<img width="1378" height="1096" alt="wireshark-spdm-screenshot" src="https://github.com/user-attachments/assets/b2afa858-ab3d-4ce9-a873-69e3214ff186" />


sysctl -w net.ipv4.ip_forward=1
nft add table nat
nft add chain nat prerouting { type nat hook prerouting priority 0 \;}
nft add chain nat postrouting { type nat hook postrouting priority 0 \;}
nft add rule nat postrouting oifname "eth0" masquerade
nmcli dev set wlan0 managed no
ip link set wlan0 down
ip link set wlan0 address 34:96:72:AF:EC:3F
ip link set wlan0 up
hostapd /etc/hostapd/hostapd.conf

ip addr add 10.5.5.1/24 dev wlan0

dnsmasq -i wlan0 --dhcp-range=10.5.5.100,10.5.5.200,2h

########################################################################
#可用wifi MAC地址，名字不重要，只检验mac地址
#NetCore 08:10:77:54:81:??
#huiyishi 34:96:72:AF:EC:3F
#TP-Link_Lx_5G cc:81:da:d7:3d:50
#!/bin/sh

/sbin/modprobe ip_conntrack_ftp

CONNECTION_TRACKING = "1"
ACCEPT_AUTH = "0"
DHCP_CLIENT = "0"
IPT = "/sbin/iptables"
INTERNET = "eth0"
LOOPBACK_INTERFACE = "lo"
IPADDR = "my.ip.address"
SUBNET_BASE = "network.address"
SUBNET_BROADCAST = "directed.broadcast"
MY_ISP = "my.isp.address.range"

NAMESERVER_1="isp.name.server.1"
NAMESERVER_2="isp.name.server.2"
NAMESERVER_3="isp.name.server.3"
POP_SERVER="isp.pop.server"
MAIL_SERVER="isp.mail.server"
NEWS_SERVER="isp.news.server"
TIME_SERVER="some.timne.server"
DHCP_SERVER="isp.dhcp.server"
SSH_CLIENT="some.ssh.client"

LOOPBACK="127.0.0.1"
CLASS_A="10.0.0.0/8"
CLASS_B="172.16.0.0/12"
CLASS_C="192.168.0.0/16"
CLASS_D_MULTICAST="224.0.0.0/4"
CLASS_E_RESERVED_NET="224.0.0.0/5"
BROADCAST_SRC="0.0.0.0"
BROADCAST_DEST="255.255.255.255"

PRIVPORTS="0:1023"
UNPRIVPORTS="1024:65535"

TRACEROUTE_SRC_PORTS="32769:65535"
TRACEROUTE_DEST_PORTS="33434:33523"

#用户规则链，其中EXT-in和out是总开关，所有的其它用户链挂到它后面，它自己最后接到系统链上。
USER_CHAINS="EXT-input                    EXT-output \
             tcp-state-flags              connection-tracking \
			 source-address-check         destination-address-check  \
			 local-dns-server-query       remote-dns-server-response \
			 local-tcp-client-request     remote-tcp-server-response  \
			 remote-tcp-client-request    local-tcp-server-response  \
			 local-udp-client-request     remote-udp-server-response  \
			 local-dhcp-client-query      remote-dhcp-server-response \
			 EXT-icmp-out                 EXT-icmp-in   \
			 EXT-log-in                   EXT-log-out  \
			 log-tcp-state"
			 
#通知内核丢弃发往广播和组播地址的ICMP echo
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts

#禁用源路由数据包
for f in /proc/sys/net/ipv4/conf/*/accept_source_route; do
    echo 0 >$f
done

#开启SYN cookie防SYN洪水攻击
echo 1 >/proc/sys/net/ipv4/tcp_syncookies

#禁用ICMP重定向输入和输出
for f in /proc/sys/net/ipv4/conf/*/accept_redirects; do
    echo 0 >$f
done
for f in /proc/sys/net/ipv4/conf/*/send_redirects; do
    echo 0 >$f 
done

#禁用源地址确认			 
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do
    echo 1 >$f 
done

#开启LOG记录不可用地址
for f in /proc/sys/net/ipv4/conf/*/log_martians; do
    echo 1 >$f 
done

#刷新系统规则链
$IPT --flush
$IPT -t nat --flush
$IPT -t mangle --flush

#删除用户自定义规则链
$IPT -X
$IPT -t nat -X
$IPT -t mangle -X

#重置默认策略为ACCEPT
$IPT --policy INPUT ACCEPT
$IPT --policy OUTPUT ACCEPT 
$IPT --policy FORWARD ACCEPT
$IPT -t nat --policy PREROUTING ACCEPT
$IPT -t nat --policy OUTPUT ACCEPT
$IPT -t nat --policy POSTROUTING ACCEPT
$IPT -t mangle --policy OUTPUT ACCEPT

if [ "$1" = "stop"]
then
echo "防火墙已经停止，这台机器正在裸奔"
exit 0
fi

#放行回环口
$IPT -A INPUT -i lo -j ACCEPT
$IPT -A OUTPUT -i lo -J ACCEPT

#设置默认策略，三链全部丢弃，虽然在前面定义，但iptables的默认策略是最后匹配else的。
$IPT --policy INPUT DROP
$IPT --policy OUTPUT DROP
$IPT --policy FORWARD DROP

#建立预定义的用户规则链
for i in $USER_CHAINS; do
    $IPT -N $i
done

#分流DNS流量到其对应处理链上
$IPT -A EXT-output -p udp --sport 53 --dport 53 \
         -j local-dns-server-query

$IPT -A EXT-input -p udp --sport 53 --dport 53 \
        -j remote-dns-server-response
		
$IPT -A EXT-output -p tcp \
        --sport $UNPRIVPORTS --dport 53 \
		-j local-dns-server-query

$IPT -A EXT-input -p tcp ! --syn \
        --sport 53 --dport $UNPRIVPORTS \
		-j remote-dns-server-query

#设置DNS处理链的规则，注意开启状态监控的话优先放行		
if [ "$CONNECTION_TRACKING" = "1" ]; then
    $IPT -A local-dns-server-query \
	    -d $NAMESERVER_1 \
		-m state --state NEW -j ACCEPT
		
    $IPT -A local-dns-server-query \
	    -d $NAMESERVER_2 \
		-m state --state NEW -j ACCEPT
		
    $IPT -A local-dns-server-query \
	    -d $NAMESERVER_3 \
		-m state --state NEW -j ACCEPT		
fi

$IPT -A local-dns-server-query \
    -d $NAMESERVER_1 -j ACCEPT
	
$IPT -A local-dns-server-query \
    -d $NAMESERVER_2 -j ACCEPT

$IPT -A local-dns-server-query \
    -d $NAMESERVER_3 -j ACCEPT

$IPT -A remote-dns-server-response \
    -s $NAMESERVER_1 -j ACCEPT
	
$IPT -A remote-dns-server-response \
    -s $NAMESERVER_2 -j ACCEPT
	
$IPT -A remote-dns-server-response \
    -s $NAMESERVER_3 -j ACCEPT

#分流本地非特权端口发起的服务请求流量和远程服务的响应流量到其对应处理链上
$IPT -A EXT-output -p tcp \
    --sport $UNPRIVPORTS \
	-j local-tcp-client-request
	
$IPT -A EXT-output -p tcp \
    --sport $UNPRIVPORTS \
	-j remote-tcp-server-response

#设置如上处理链的规则（各类TCP常用服务），注意开启状态监控的话优先放行	
##开放本地发起的SSH请求流量
if [ "$CONNECTION_TRACKING" = "1" ]; then
    $IPT -A local-tcp-client-request -p tcp \
	    -d <selected host> --dport 22 \
		-m state --state NEW
		-j ACCEPT
fi

$IPT -A local-tcp-client-request -p tcp \
    -d <selected host> --dport 22 \
	-j ACCEPT
	
$IPT -A local-tcp-client-request -p tcp ! --syn \
    -s <selected host> --dport 22 \
	-j ACCEPT
	
##开放本地发起的http/https/ftp服务流量
if [ "$CONNECTION_TRACKING" = "1" ]; then
    $IPT -A local-tcp-client-request -p tcp \
	    -m multiport --destination-port 80,443,21 \
		--syn -m state --state NEW \
		-j ACCEPT
fi

$IPT -A local-tcp-client-request -p TCP \
    -m multiport --destination-port 80,443,21 \
	-j ACCEPT
	
$IPT -A local-tcp-client-response -p TCP \
    -m multiport --destination-port 80,443,21 ! --syn \
	-j ACCEPT

##开放本地发起的邮件服务请求流量
if [ "$CONNECTION_TRACKING" = "1" ]; then
    -d $POP_SERVER --dport 110 \
	-m state --state NEW \
	-j ACCEPT
fi

$IPT -A local-tcp-client-request -p tcp \
    -d $POP_SERVER --dport 110 \
	-j ACCEPT
	
$IPT -A local-tcp-client-response -p tcp ! --syn \
    -d $POP_SERVER --dport 110 \
	-j ACCEPT

##开放本地发起的SMTP服务请求流量
if [ "CONNECTION_TRACKING" = "1" ]; then
    $IPT -A local-tcp-client-request -p tcp \
	    -d $MAIL_SERVER -dport 25 \
		-m state --state NEW \
		-j ACCEPT
fi

$IPT -A local-tcp-client-request -p tcp \
    -d $MAIL_SERVER --dport 25 \
	-j ACCEPT
	
$IPT -A remote-tcp-server-response -p tcp ! --syn \
    -s $MAIL_SERVER --dport 25 \
	-j ACCEPT

##开放本地发起的NEWS服务请求流量
if [ "$CONNECTION_TRACKING" = "1" ]; then
    $IPT -A local-tcp-client-request -p tcp \
	    -d $NEWS_SERVER --dport 119 \
		-m state --state NEW \
		-j ACCEPT
fi

$IPT -A local-tcp-client-request -p tcp \
    -d $NEWS_SERVER --dport 119 \
	-j ACCEPT
	
$IPT -A remote-udp-server-response -p tcp ! --syn \
    -s $NEWS_SERVER --sport 119 \
	-j ACCEPT

##开放本地发出的所有主动连接
if [ "$CONNECTION_TRACKING" = "1" ]; then
    $IPT -A local-tcp-client-request -p tcp \
	    --dport $UNPRIVPORTS \
		-m state --state NEW \
		-j ACCEPT
fi

$IPT -A local-tcp-client-request -p tcp \
	--dport $UNPRIVPORTS -j ACCEPT
		
$IPT -A remote-dhcp-server-response -p tcp ! --syn \
    --sport $UNPRIVPORTS -j ACCEPT
	
##分流本地服务器的接入流量和响应到对应处理链	
$IPT -A EXT-input -p tcp \
    --sport $UNPRIVPORTS \
	-j remote-tcp-client-request
	
$IPT -A EXT-output -p tcp ! --syn \
    --dport $UNPRIVPORTS \
	-j local-tcp-client-response
	
##开本地FTP服务流量
$IPT -A EXT-input -p tcp \
    --sport 20 --dport $UNPRIVPORTS \
	-j ACCEPT
	
$IPT -A EXT-output -p tcp ! --syn \
    --sport $UNPRIVPORTS --dport 20 \
	-j ACCEPT

##开本地SSH服务流量
if [ "$CONNECTION_TRACKING" = "1" ]; then
    $IPT -A remote-tcp-client-request -p tcp \
	    -s <selected host> --destination -port 22 \
	    -m state --state NEW \
		-j ACCEPT
fi

$IPT -A remote-tcp-client-request -p tcp \
    -s <selected host> --destination-port 22 \
	-j ACCEPT
	
$IPT -A local-tcp-client-request -p tcp ! --syn \
    --source-port 22 -d <selected host> \
	-j ACCEPT

##开本地AUTH服务流量	
if [ "$ACCEPT_AUTH" = "0" ]; then 
    $IPT -A remote-tcp-client-request -p tcp \
	    --destination-port 113 \
		-j REJECT --reject-with tcp-restet
else
    $IPT -A remote-tcp-client-request -p tcp \
	    --destination-port 113 \
		-j ACCEPT
	$IPT -A local-tcp-client-response -p tcp ! --syn \
	    --source-port 113 \
		--j ACCEPT
fi

#分流UDP服务到对应规则链
$IPT -A EXT-output -p udp \
    --sport $UNPRIVPORTS \
	-j local-udp-client-request

$IPT -A EXT-input -p udp \
    --dport $UNPRIVPORTS \
	-j remote-udp-server-response
	
#设置如上处理链的规则（各类UDP常用服务），注意开启状态监控的话优先放行
##开本地NTP服务接入和响应流量
if [ "$CONNECTION_TRACKING" = "1" ]; then
    $IPT -A local-udp-client-request -p udp \
	    -d $TIME_SERVER --dport 123 \
		-m state --state NEW \
		-j ACCEPT
fi

$IPT -A local-udp-client-request -p udp \
    -d $TIME_SERVER --dport 123 \
	-j ACCEPT
	
$IPT -A remote-udp-server-response -p tcp \
    -s $TIME_SERVER --sport 123 \
	-j ACCEPT
	
#分流ICMP流量到其对应处理链上
$IPT -A EXT-input -p icmp -j EXT-icmp-in
$IPT -A EXT-out -p icmp -j EXT-icmp-out

$IPT -A EXT-icmp-in --fragment -j LOG \
    --log-prefix "传入ICMP帧："
	
$IPT -A EXT-icmp-out --fragment -j LOG \
    --log-prefix "传出ICMP帧："
	
#设置ICMP传出规则为丢弃
$IPT -A EXT-icmp-out --fragment -j DROP

#开本地发出的ping请求流量和响应
if [ "$CONNECTION_TRACKING" = "1" ]; then
    $IPT -A EXT-icmp-out -p icmp \
	    --icmp-type echo-request \
		-m state --state NEW
		-j ACCEPT
fi

$IPT -A EXT-icmp-out -p icmp \
    --icmp-type echo-request -j ACCEPT
	
$IPT -A EXT-icmp-in -p icmp \
    --icmp-type echo-reply -j ACCEPT

#只响应ISP服务商的ping包接入	
if [ "$CONNECTION_TRACKING" = "1" ]; then
    $IPT -A EXT-icmp-in -p icmp \
	    -s $MY_ISP \
		--icmp-type echo-request \
		-m state --state NEW \
		-j ACCEPT
fi

$IPT -A EXT-icmp-in -p icmp \
    --icmp-type echo-request \
	-s $MY_ISP -j ACCEPT
	
$IPT -A EXT-icmp-out -p icmp \
    --icmp-type echo-reply \
	-d $MY_ISP -j ACCEPT

#开网络不可达回显
$IPT -A EXT-icmp-out -p icmp \
    --icmp-type fragmentation-needed -j ACCEPT

$IPT -A EXT-icmp-in -p icmp \
    --icmp-type destination-unreachable -j ACCEPT

#开TTL用尽回显		
$IPT -A EXT-icmp-out -p icmp \
    --icmp-type parameter-problem -j ACCEPT

$IPT -A EXT-icmp-in -p icmp \
    --icmp-type parameter-problem -j ACCEPT
	
#检查TCP标志位，分流妖包到对应的日志记录处理链
$IPT -A tcp-client-flags -p tcp --tcp-flags ALL NONE -j log-tcp-state

$IPT -A tcp-state-flags -p tcp --tcp-flags SYN,FIN SYN,FIN -j log-tcp-state

$IPT -A tcp-state-flags -p tcp --tcp-flags SYN,RST SYN,RST -j log-tcp-state

$IPT -A tcp-state-flags -p tcp --tcp-flags FIN,RST FIN,RST -j log-tcp-state

$IPT -A tcp-state-flags -p tcp --tcp-flags ACK,FIN FIN -j log-tcp-state

$IPT -A tcp-state-flags -p tcp --tcp-flags ACK,PSH PSH -j log-tcp-state

$IPT -A tcp-state-flags -p tcp --tcp-flags ACK,URG URG -j log-tcp-state

#处理妖包，记录日志
$IPT -A log-tcp-state -p tcp -j LOG \
    --log-prefix "TCP妖态:" \
	--log-ip-options --log-tcp-options
	
$IPT -A log-tcp-state -j DROP

#开状态记录免检放行后续包
if [ "$CONNECTION_TRACKING" = "1" ]; then 
    $IPT -A connection-tracking -m state \
	    --state ESTABLISHED,RELATED \
	    -j ACCEPT
	
	$IPT -A connection-tracking -m state --state INVALID \
	    -j LOG --log-prefix "坏包:"
		
	$IPT -A connection-tracking -m state --state INVALID -j DROP
fi

#若本地使用DHCP服务，放行流量
if [ "$DHCP_CLIENT" = "1" ]; then
    $IPT -A local-dhcp-client-query \
	    -s $BROADCAST_SRC \
		-d $BROADCAST_DEST -j ACCEPT
		
	$IPT -A remote-dhcp-server-response \
	    -s $BROADCAST_SRC \
		-d $BROADCAST_DEST -j ACCEPT
		
	$IPT -A local-dhcp-client-query \
	    -s $BROADCAST_SRC \
		-d $DHCP_SERVER -j ACCEPT
		
	$IPT -A remote-dhcp-server-response \
	    -s $DHCP_SERVER \
		-d $BROADCAST_DEST -j ACCEPT
		
    $IPT -A remote-dhcp-server-response \
	    -s $DHCP_SERVER -j ACCEPT
		
	$IPT -A local-dhcp-client-query \
	    -s $IPADDR \
		-d $DHCP_SERVER -j ACCEPT
fi

#配置源地址欺骗链的规则
$IPT -A source-address-check -s $CLASS_A -j DROP
$IPT -A source-address-check -s $CLASS_B -j DROP
$IPT -A source-address-check -s $CLASS_C -j DROP
$IPT -A source-address-check -s $CLASS_D_MULTICAST -j DROP
$IPT -A source-address-check -s $CLASS_E_RESERVED_NET -j DROP
$IPT -A source-address-check -s $LOOPBACK -j DROP
$IPT -A source-address-check -s 0.0.0.0/8 -j DROP
$IPT -A source-address-check -s 169.254.0.0/16 -j DROP
$IPT -A source-address-check -s 192.0.2.0/24 -j DROP

#配置目的地址检查链规则
$IPT -A destination-address-check -d $BROADCAST_DEST -j DROP
$IPT -A destination-address-check -d $SUBNET_BASE -j DROP
$IPT -A destination-address-check -d $SUBNET_BROADCAST -j DROP
$IPT -A destination-address-check ! -p udb \
    -d $CLASS_D_MULTICAST -j DROP

#对默认丢弃流量的日志记录规则	
$IPT -A EXT-log-in -p icmp \
    ! --icmp-type echo-request -m limit -j LOG
	
$IPT -A EXT-log-in -p tcp \
    --dport 0:19 -j LOG
	
$IPT -A EXT-log-in -p tcp \
    --dport 24 -j LOG
	
$IPT -A EXT-log-in -p tcp \
    --dport 26:78 -j LOG
	
$IPT -A EXT-log-in -p tcp \
    --dport  81:109 -j LOG
	
$IPT -A EXT-log-in -p tcp \
    --dport 112:136 -j LOG
	
$IPT -A EXT-log-in -p tcp \
    --dport 140:142 -j LOG
	
$IPT -A EXT-log-in -p tcp \
    --dport 144:442 -j LOG
	
$IPT -A EXT-log-in -p tcp \
    --dport 444:65535 -j LOG
	
$IPT -A EXT-log-in -p udp \
    --dport 0:110 -j LOG
	
$IPT -A EXT-log-in -p udp \
    --dport 112:160 -j LOG
	
$IPT -A EXT-log-in -p udp \
    --dport 163:634 -j LOG
	
$IPT -A EXT-log-in -p udp \
    --dport 636:5631 -j LOG
	
$IPT -A EXT-log-in -p udp \
    --dport 5633:31336 -j LOG
	
$IPT -A EXT-log-in -p udp \
    --sport $TRACEROUTE_SRC_PORTS \
	--dport $TRACEROUTE_DEST_PORTS -j LOG
	
$IPT -A EXT-log-in -p udp \
    --dport 33434:65535 -j LOG
	
$IPT -A EXT-log-out -p icmp \
    --icmp-type destination-unreachable -j DROP
	
$IPT -A EXT-log-out -j LOG

#挂载组装所有规则链到对应当位置
$IPT -A INPUT -p tcp -j tcp-state-flags
$IPT -A OUTPUT -p tcp -j tcp-state-flags

if [ "$CONNECTION_TRACKING" = "1" ]; then 
    $IPT -A INPUT -j connection-tracking
	$IPT -A OUTPUT -j connection-tracking
fi

if [ "$DHCP_CLIENT" = "1" ]; then 
    $IPT -A INPUT -i $INTERNET -p udp \
	    --sport 67 --dport 68 -j remote-dhcp-server-response
	$IPT -A OUTPUT -o $INTERNET -p udp \
	    --sport 68 --dport 67 -j local-dhcp-client-query
fi

$IPT -A INPUT ! -p tcp -j source-address-check
$IPT -A INPUT -p tcp --syn -j source-address-check
$IPT -A INPUT -j destination-address-check

$IPT -A OUTPUT -j destination-address-check

$IPT -A INPUT -i $INTERNET -d $IPADDR -j EXT-input

$IPT -A INPUT -i $INTERNET -p udp -d $CLASS_D_MULTICAST -j [DORP | ACCECP]
$IPT -A OUTPUT -i $INTERNET -p udp -s $IPADDR -d $CLASS_D_MULTICAST -j [DORP | ACCECP]

$IPT -A OUTPUT -o $INTERNET -s $IPADDR -j EXT-output

$IPT -A INPUT -j EXT-log-in 
$IPT -A OUTPUT -j EXT-log-out

exit 0
#!/bin/sh

NFT="/usr/local/sbin/nft"

#通知内核丢弃发往广播和组播地址的ICMP echo
echo 1 >/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts

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

#禁用源地址确认		
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do
    echo 1 >$f 
done

#开启LOG记录不可用地址
for f in /proc/sys/net/ipv4/conf/*/log_martians; do
    echo 1 >$f 
done

#清空删除现有表和链（必须先清除链）
for i in '$NFT list tables | awk '{print $2}''
do
    echo "清空 ${i}"
	$NFT flush table ${i}
	for j in '$NFT list table ${i} | grep chain | awk '{print $2}''
	do
	    echo "...正在从${i}表中删除${j}链"
		$NFT delete chain ${i} ${j}
	done
	echo "正在删除${i}"
	$NFT delete table ${i}
done

#如果选择关闭防火墙
if [ "$1" = "stop" ]; then
    echo "防火墙已经完全关闭，机器正在裸奔"
	exit 0
fi

#导入各表和规则链
$NFT -f setup-tables
$NFT -f localhost-policy
$NFT -f connectionstate-policy
$NFT -f invalid-policy
$NFT -f dns-policy
$NFT -f tcp-client-policy
$NFT -f tcp-server-policy
$NFT -f icmp-policy
$NFT -f log-policy

#最后导入默认规则，nftables不像iptables，它不支持默认规则（iptables的用户自定义链也不支持默认规则）
$NFT -f default-policy
#!/usr/bin/env python3

import os,sys
import argparse

def firewall_setup():
	os.system("ifconfig enp2s0 192.168.88.1 up")
	os.system("echo \"1\" >/proc/sys/net/ipv4/ip_forward")
	os.system("route add -net 192.168.0.0 netmask 255.255.255.0 gw 192.168.0.100")
	os.system("route add -net 192.168.88.0/24 gw 192.168.88.1")

def internet_host_setup():
	os.system("ifconfig eno1 down")
	os.system("ifconfig enp2s0 192.168.88.2 up")
	os.system("route add default gw 192.168.88.1")

def test_host_setup():
	os.system("ifconfig eno1 down")
	os.system("ifconfig enp2s0 192.168.88.3 up")
	os.system("route add default gw 192.168.88.1")

def dns_allow():
	print("Allow DNS")
	os.system("iptables -A INPUT -p udp  --sport 1024:65535  --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT")
	os.system("iptables -A OUTPUT -p udp  --sport 53  --dport 1024:65535 -m state --state NEW,ESTABLISHED -j ACCEPT")
	os.system("iptables -A INPUT -p udp  --sport 53  --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT")
	os.system("iptables -A OUTPUT -p udp  --sport 53  --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT")

	os.system("iptables -A INPUT -p tcp  --sport 1024:65535  --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT")
	os.system("iptables -A OUTPUT -p tcp  --sport 53  --dport 1024:65535 -m state --state NEW,ESTABLISHED -j ACCEPT")
	
	os.system("iptables -A OUTPUT -p udp  --sport 1024:65535  --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT")
	os.system("iptables -A INPUT -p udp  --sport 53  --dport 1024:65535 -m state --state NEW,ESTABLISHED -j ACCEPT")
	os.system("iptables -A OUTPUT-p tcp  --sport 1024:65535  --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT")
	os.system("iptables -A INPUT -p tcp  --sport 53  --dport 1024:65535 -m state --state NEW,ESTABLISHED -j ACCEPT")

def dhcp_allow():
	print("Allow DHCP")
	os.system("iptables -A INPUT -m udp -p udp --sport 67:68 --dport 67:68 -m state --state NEW,ESTABLISHED -j ACCEPT")
	os.system("iptables -A OUTPUT -m udp -p udp --sport 67:68 --dport 67:68 -m state --state NEW,ESTABLISHED -j ACCEPT")


def drop_all():
	print("Setting default policies to DROP")
	os.system("iptables -P INPUT DROP")
	os.system("iptables -P FORWARD DROP")
	os.system("iptables -P OUTPUT DROP")

def drop_outside_to_internal():
	print("Drop all packets with a source address from the outside matching internal network.")
	os.system("iptables -A INPUT -i eno1 -s 192.168.88.0/24 -p all -j DROP")

def drop_outside_ping():
    print("Drop ping icmp")
    os.system("iptables -I INPUT -p icmp --icmp-type Echo-Request -j DROP")
    os.system("iptables -I INPUT -p icmp --icmp-type Echo-Reply -j ACCEPT")
    os.system("iptables -I INPUT -p icmp --icmp-type destination-Unreachable -j ACCEPT")

def drop_package_from_outside_to_firewall():
    print("Drop all packets destined for the firewall host from the outside")
    os.system("iptables -A INPUT -i eno1 -d 192.168.0. -j DROP")
    
def drop_SYN_to_high_port():
    print("reject those connections that are coming the “wrong” way")
    os.system("iptables -A INPUT -p tcp --syn --dport 1024:65535 -j DROP")

def clear_iptables():
	os.system("iptables -F")
	os.system("iptables -P INPUT ACCEPT")
	os.system("iptables -P OUTPUT ACCEPT")
	os.system("iptables -P FORWARD ACCEPT")
	os.system("iptables -t nat -F")
	os.system("iptables -t mangle -F")
	os.system("iptables -X")

def allow_ssh_www():
    # HTTP/HTTPS
    os.system("iptables -A INPUT -m tcp -p tcp  --sport 443 -m conntrack --ctstate ESTABLISHED -j ACCEPT")
    os.system("iptables -A INPUT -m tcp -p tcp  --sport 80 -m conntrack --ctstate ESTABLISHED -j ACCEPT")
    
    # SSH
    os.system("iptables -A INPUT -m tcp -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT")

    # HTTP/HTTPS
    os.system("iptables -A OUTPUT -m tcp -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT")
    os.system("iptables -A OUTPUT -m tcp -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT")

    # SSH
    os.system("iptables -A OUTPUT -m tcp -p tcp --sport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT")

def main():
    clear_iptables()
    firewall_setup()
    drop_all()
    drop_package_from_outside_to_firewall()
    drop_SYN_to_high_port()
    drop_outside_ping()
    dns_allow()
    dhcp_allow()
    drop_outside_to_internal()
    
	




if __name__=='__main__':
	main()

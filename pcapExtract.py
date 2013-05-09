import socket
import dpkt
import sys

pcapReader = dpkt.pcap.Reader(file(sys.argv[1], "rb"))


# gets the TCP flags from a given TCP packet. 
# Flags are put into a dictionary in the format name: true/false
def getTCPFlags(tcp):
	fin_flag = (tcp.flags & dpkt.tcp.TH_FIN) != 0
	syn_flag = (tcp.flags & dpkt.tcp.TH_SYN) != 0
	rst_flag = (tcp.flags & dpkt.tcp.TH_RST) != 0
	psh_flag = (tcp.flags & dpkt.tcp.TH_PUSH) != 0
	ack_flag = (tcp.flags & dpkt.tcp.TH_ACK) != 0
	urg_flag = (tcp.flags & dpkt.tcp.TH_URG) != 0
	ece_flag = (tcp.flags & dpkt.tcp.TH_ECE) != 0
	cwr_flag = (tcp.flags & dpkt.tcp.TH_CWR) != 0
	flags = {'fin': fin_flag, 'syn': syn_flag, 'rst': rst_flag, 
		'psh': psh_flag, 'ack': ack_flag, 'urg': urg_flag, 
		'ece': ece_flag, 'cwr': cwr_flag}
	return flags


for ts, data in pcapReader:
    ether = dpkt.ethernet.Ethernet(data)
    if ether.type != dpkt.ethernet.ETH_TYPE_IP: raise
    ip = ether.data
    src = socket.inet_ntoa(ip.src)
    dst = socket.inet_ntoa(ip.dst)
    flags = getTCPFlags(ip.data)
    print "\n%s -> %s" % (src, dst) 
    print "Packet data length: ", len(data)
    print "TCP Flags: "
    print flags
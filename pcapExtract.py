import socket
import dpkt
import sys
from py2neo import neo4j

pcapReader = dpkt.pcap.Reader(file(sys.argv[1], "rb"))
graph_db = neo4j.GraphDatabaseService("http://localhost:7474/db/data/")

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

graph_db.clear()
for ts, data in pcapReader:
    ether = dpkt.ethernet.Ethernet(data)
    if ether.type != dpkt.ethernet.ETH_TYPE_IP: raise
    ip = ether.data
    src = socket.inet_ntoa(ip.src)
    dst = socket.inet_ntoa(ip.dst)
    flags = getTCPFlags(ip.data)
    # print "\n%s -> %s" % (src, dst) 
    # print "Packet data length: ", len(data)
    # print "TCP Flags: "
    # print flags
    nodeIndex = graph_db.get_or_create_index(neo4j.Node, "NodeIndex")
    srcNode = nodeIndex.get_or_create("ipaddr", src, {"ipaddr": src})
    dstNode = nodeIndex.get_or_create("ipaddr", dst, {"ipaddr": dst})
    graph_db.create((srcNode, "PACKET_TO", dstNode, {"fin": flags["fin"], 
        "syn": flags["syn"], "rst": flags["rst"], "psh": flags["psh"], 
        "ack": flags["ack"], "urg": flags["urg"], "ece": flags["ece"], 
        "cwr":flags["cwr"], "length":len(data)}))

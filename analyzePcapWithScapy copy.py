from scapy.all import *
import re

def analyzePcap(filepath):

    s1 = PcapReader(filepath)

    No = 1
    try:
        # data 是以太网 数据包
        data = s1.read_packet()

        while data is not None:
            if(is_icmp(data)): 
                ip_packet = data.payload
                ip_payload = ip_packet.payload
                ip_payload_hexStr = ip_payload.original.hex()
                src = ip_packet.fields['src']
                # 根据ip_payload的十六进制数据查找数据包
                if(src == '10.0.2.8' and ip_payload_hexStr == '9f16b7670a94f877b2aa440ae28b41ad6d83ea67915bdee068e0f2968f5f05aa4f' ):
                    print(type(ip_payload_hexStr))   # <class 'str'>
                    print(filepath)
                    print(No)

           
            data = s1.read_packet() 
            No += 1

        s1.close()
    except Exception as e:
        print(e)
    #print(type(data.payload))  #==><class 'scapy.layers.inet.IP'>  可以使用 help(scapy.layers.inet.IP) 查看帮助文档


def is_ipv4(data):
    ip_packet = data.payload
    return data.fields['type'] == 2048 and ip_packet.fields['version'] == 4

def is_ipv4_tcp(data):
    
    ip_packet = data.payload
    return  data.fields['type'] == 2048 and ip_packet.fields['version'] == 4 and ip_packet.fields['proto'] == 6

def get_filelist(dir):

    if os.path.isfile(dir):
        try:
            analyzePcap(dir)        
        except Scapy_Exception as e:
            pass

    elif os.path.isdir(dir):
        for s in os.listdir(dir):
            newDir = os.path.join(dir, s)
            get_filelist(newDir)


def is_icmp(data):

    ip_packet = data.payload
    data_fields = data.fields

    # linux ICMPv4
    if 'proto' in data_fields.keys(
    ) and data_fields['proto'] == 2048 and ip_packet.fields['proto'] == 1:
        return True

    # Destination unreachable ICMPv4
    if data_fields['type'] == 2 and ip_packet.fields['proto'] == 1:
        return True

    # ICMPv4
    if data_fields['type'] == 2048 and ip_packet.fields['proto'] == 1:
        return True

    # ICMPv6
    if data_fields['type'] == 34525 and ip_packet.fields['nh'] == 58:
        return True

    return False

get_filelist('C:\\HELK\\extractFeatures\\pcap_dir\\negative-icmp')


            
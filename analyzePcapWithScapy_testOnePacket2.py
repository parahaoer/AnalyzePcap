from scapy.all import *
from collections import Counter 
import struct
import re

def analyzePcap(filepath):

    s1 = PcapReader(filepath)

    # data 是以太网 数据包
    data = s1.read_packet()
    
    print(len(data[IP]))   # 64, 表示 IP包有64个字节

    dec_list = bytes_to_int(raw(data[IP]))
    print(dec_list)
    print(Counter(dec_list))   
    print(Counter(raw(data[IP]))) # Counter(dec_list) 与  Counter(raw(data[IP])) 内容相同  
    # if(is_ipv4_tcp(data)):
    #     print("tcp")

    # if(hasFeature01(data)):
    #     print("No." + str(No) + " maybe RFB 协议")

    # elif(hasFeature03(data)):
    #     print("No." + str(No) + " maybe pointerEvent")

    # elif(hasFeature02(data)):
    #     print("No." + str(No) + " maybe security types supported package")

    # elif(hasFeature04(data)):
    #     print("No." + str(No) + " maybe KeyEvent")



    #print(type(data.payload))  #==><class 'scapy.layers.inet.IP'>  可以使用 help(scapy.layers.inet.IP) 查看帮助文档


def bytes_to_int(bytes):
    result = []
 
    for dec in bytes:
        # result = result * 256 + int(b)
        result.append(dec)
  
    return result

def is_ipv4_tcp(data):
    
    ip_packet = data.payload
    return ip_packet.fields['version'] == 4 and ip_packet.fields['proto'] == 6
    

def getTcpPayloadLen(data):
    ip_packet = data.payload
    tcp_packet = ip_packet.payload

    ip_header_len = ip_packet.fields['ihl'] * 4
    ip_len = ip_packet.fields['len']
    tcp_len = ip_len - ip_header_len
    tcp_header_len = tcp_packet.fields['dataofs'] * 4
    tcp_payload_len = tcp_len - tcp_header_len
    # print(tcp_payload_len)
    return tcp_payload_len

def getTcpPayload(data):
    ip_packet = data.payload
    tcp_packet = ip_packet.payload
    tcp_payload = tcp_packet.payload

    '''
        tcp_payload.original 与 tcp_payload.fields['load'] 返回的都是 bytes对象
        通过下标获取bytes对象的某一个字节内容，是十进制的，而不是十六进制数据。
    '''
    # print(tcp_payload.original[0])  # 82 , 转换成16进制是0x52, 与wireshark 中显示的相同。
    # print(tcp_payload.original) # b'RFB 003.008\n', 结果是以字节的值为ASCII值转换成相应的字符串（字符串前边的b表示是bytes对象）。
    # print(tcp_payload.original.hex()) 
    # print(type(tcp_payload.original))
    # print(type(tcp_payload.fields['load']))
    return tcp_payload.original

# tcp_payload 的长度为12字节， 且包含字符串“RFB”
def hasFeature01(data):
    tcp_payload = getTcpPayload(data)
    tcp_payload_len = getTcpPayloadLen(data)
    return tcp_payload_len == 12 and re.search("RFB", str(tcp_payload))


# tcp_payload的第一个字节内容等于tcp_payload的长度 减一。则该数据包是服务器向客户端发送其支持的security type
def hasFeature02(data):
    tcp_payload = getTcpPayload(data)
    tcp_payload_len = getTcpPayloadLen(data)
    
    return  tcp_payload[0] != 0 and tcp_payload[0] == tcp_payload_len -1


# tcp_payload的长度为6字节，且tcp_payload的第一个字节内容为5.则该数据包是一个pointerEvent
def hasFeature03(data):
    tcp_payload = getTcpPayload(data)
    tcp_payload_len = getTcpPayloadLen(data)    

    return tcp_payload_len == 6 and tcp_payload[0] == 5


# tcp_payload的长度为8字节，且tcp_payload的第一个字节内容为4.则该数据包是一个KeyEvent.
def hasFeature04(data):
    tcp_payload = getTcpPayload(data)
    tcp_payload_len = getTcpPayloadLen(data)    

    return tcp_payload_len == 8 and tcp_payload[0] == 4

# analyzePcap('C:\\Users\\dong\\Desktop\\workAtHome\\vnc协议\\vnc_concise.pcap')
analyzePcap('C:\\Users\\dong\\Documents\\WeChat Files\\wxid_njmfjwrjvua322\\FileStorage\\File\\2020-07\\vnc-sample.pcap')

            
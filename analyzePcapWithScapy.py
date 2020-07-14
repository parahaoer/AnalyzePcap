from scapy.all import *
import re

def analyzePcap(filepath):

    s1 = PcapReader(filepath)

    ftxt = open('scapy_analyze_result/result_feature_great_than_30.txt','a', encoding="utf-8")
    write_line = []
    vnc_feature_count = 0
    global vnc_file_count

    No = 1
    try:
        # data 是以太网 数据包
        data = s1.read_packet()

        while data is not None:
            if(is_ipv4_tcp(data)):

                if(hasFeature01(data)):
                    write_line.append("No." + str(No) + " maybe RFB 协议")
                    vnc_feature_count +=1

                elif(hasFeature03(data)):
                    write_line.append("No." + str(No) + " maybe pointerEvent")
                    vnc_feature_count +=1

                elif(hasFeature02(data)):
                    write_line.append("No." + str(No) + " maybe security types supported package")
                    vnc_feature_count +=1
            
                elif(hasFeature04(data)):
                    write_line.append("No." + str(No) + " maybe KeyEvent")
                    vnc_feature_count +=1
            
            data = s1.read_packet() 
            No += 1

        s1.close()
    except:
        pass
    
    if(vnc_feature_count >= 30):

        vnc_file_count += 1
        ftxt.write(filepath + "\n")
        ftxt.write("vnc_feature_count=" + str(vnc_feature_count) + "\n")
        for line in write_line:
            ftxt.write("\t" + line + "\n") 
    ftxt.close()

    #print(type(data.payload))  #==><class 'scapy.layers.inet.IP'>  可以使用 help(scapy.layers.inet.IP) 查看帮助文档

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
    
    return tcp_payload[0] != 0 and tcp_payload[0] == tcp_payload_len -1


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

vnc_file_count = 0

get_filelist('C:\\Users\\dong\\Desktop\\workAtHome\\dridex\\dridexPcap')

print(vnc_file_count)

            
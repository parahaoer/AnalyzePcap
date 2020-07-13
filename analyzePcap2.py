
#!/usr/bin/env python
#coding=utf-8

import struct
import os


def is_ipv4_tcp(data):
    """传入数据帧，对数据帧的以太网层的type字段以及ip的protocol字段进行判断，若为IPV4下的tcp协议
    返回TRUE，反之则为FALSE"""
    return struct.unpack('H', data[12:14])[0] == 8 and data[23] == 6


def analyzePcap(filepath):

    fpcap = open(filepath,'rb')
    ftxt = open('result_feature_great_than_30.txt','a', encoding="utf-8")
    string_data = fpcap.read()

    #pcap文件的数据包解析
    step = 0
    packet_num = 1
    packet_data = []
    write_line = []

    vnc_feature_count = 0
    global vnc_file_count

    pcap_packet_header = {}
    i =24

    while(i<len(string_data)):
        
        #数据包头各个字段
        pcap_packet_header['GMTtime'] = string_data[i:i+4]
        pcap_packet_header['MicroTime'] = string_data[i+4:i+8]
        pcap_packet_header['caplen'] = string_data[i+8:i+12]
        pcap_packet_header['len'] = string_data[i+12:i+16]

        #求出此包的包长len
        packet_len = struct.unpack('I',pcap_packet_header['len'])[0]
        #写入此包数据
        data = string_data[i+16:i+16+packet_len]
        
        if(is_ipv4_tcp(data)):
            if(data[-8] == 4):
                write_line.append("\tNo."+str(packet_num) + " packet maybe vnc keyevent!\n")
                write_line.append("\tthe data:"+repr(data) + "\n")
                vnc_feature_count = vnc_feature_count + 1
                print(str(packet_num) + " maybe vnc keyevent!")
            elif(data[-6] == 5):
                write_line.append("\tNo."+ str(packet_num) + " packet maybe vnc pointevent!\n")
                write_line.append("\tthe data:"+repr(data) + "\n")
                vnc_feature_count = vnc_feature_count + 1
                print(str(packet_num) + " maybe vnc pointevent!")
                
        i = i+ packet_len+16
        packet_num+=1  
        
    if(vnc_feature_count >= 30):

        vnc_file_count += 1
        ftxt.write(filepath + "\n")
        ftxt.write("vnc_feature_count=" + str(vnc_feature_count) + "\n")
        for line in write_line:
            ftxt.write(line) 

    ftxt.close()
    fpcap.close()


def get_filelist(dir):

    if os.path.isfile(dir):
        analyzePcap(dir)        

    elif os.path.isdir(dir):
        for s in os.listdir(dir):
            newDir = os.path.join(dir, s)
            get_filelist(newDir)

vnc_file_count = 0

get_filelist('C:\\Users\\dong\\Desktop\\workAtHome\\dridex\\dridexPcap')

print(vnc_file_count)

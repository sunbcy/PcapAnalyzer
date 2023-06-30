# -*-coding:utf-8-*-
from scapy.all import *
from scapy_ssl_tls.ssl_tls import *
import re
import os
from urllib.parse import unquote
import traceback
from __init__ import files, src_host_list
import logging
logging.captureWarnings(True)  # 去掉命令行中的WARNING
logging.basicConfig(filename="PcapAnalyser.log",
                    datefmt="%Y/%m/%d %H:%M:%S",
                    format='%(asctime)s - %(name)s - %(levelname)s - %(lineno)d - %(module)s - %(message)s',
                    level=logging.INFO,
                    encoding='utf-8')
logger = logging.getLogger(__name__)

"""
端口范围：0~65535，
公认端口（System Ports）：0~1023是被RFC 3232规定好的，用于特定协议；
注册端口（User Ports）：1024-49151，使用这类端口号必须在IANA按照规定登记，以防止重复；
动态/私有端口（Dynamic and/or Private Ports）：49152-65535，被操作系统动态分配；

常见应用层协议：
FTP、Telnet、SMTP、HTTP、RIP、NFS、DNS

常见表示层协议：
JPEG、ASCLL、GIF、DES、MPEG

常见会话层协议：
RPC：没有默认端口,它是动态获取端口的。远程过程调用协议。 基于Socket，它是一种通过网络从远程计算机程序上请求服务，而不需要了解底层网络技术的协议。采用C/S模式。
SQL、NFS

常见传输层协议：
TCP:在TCP层，有个FLAGS字段,对于我们日常的分析有用的就是前面的五个字段。它们的含义是：SYN表示建立连接，FIN表示关闭连接，ACK表示响应，PSH表示有DATA数据传输，RST表示连接重置。
UDP、SPX
 
常见网络层协议：
IP：
IPX、路由器和三层交换机工作
ICMP协议：因特网控制信息协议。
 作用：用于在IP主机、路由器之间传递控制消息。
 控制消息：是指网络通不通、主机是否可达、路由是否可用等网络本身的消息。这些控制消息虽然并不传输用户数据，但是对于用户数据的传递起着重要的作用。
 不同的ICMP类型代表不同意义得记住。ICMP 会和 PING 、Traceroute命令结合。
ARP协议：地址解析协议。作用：通过  IP地址（逻辑地址）寻找MAC地址（物理地址），也就是将  32位IP地址 解析成  48位以太网 的操作。
RARP协议：反地址解析协议。 作用：也就是将 48位以太网 解析成 32位IP地址。
RIP： 路由信息协议。端口号：520。 属于内部路由协议。
OSPF：开放最短路径优先协议。端口号：89。 属于内部路由协议。
BGP： 边界网关协议。端口号：179。 属于外部路由协议。
EIGRP： 增强内部网关路由协议。端口号：88。 属于内部路由协议。


常见数据链路层协议：
PPP：点对点协议，主要是用来通过  拨号  或  专线  方式建立点对点连接发送数据，使其成为各种  主机、网桥和路由器  之间简单连接的一种共通的解决方案。
LCP（配置协商）：链路控制协议，是PPP协议的一个子集，在PPP通信中，发送端和接收端通过发送LCP包来确定那些在数据传输中的必要信息
HDLC：MAC
IEEE802.3/.2、ATM

常见物理层协议：
RS232、V.35、RJ-45、FDDI

[TCP]协议常见端口：
FTP：20/21号端口（文件传输协议 20：数据/21：控制）
SSH：22
Telnet：23号端口（远程登陆协议）
SMTP：25号端口（简单邮件传送协议）
DHCP：67
TFTP：69
Kerberos:88（包括屏幕共享认证）
POP3：110号端口（接收邮件）
netbios-ssn:139,服务器信息块 (SMB)
IMAP4： 端口号：143 。交互式数据消息访问协议第4版。 基本功能和POP3 一样，提供摘要浏览，读取后仍在服务器保留邮件。
SNMP：162
HTTP：80号端口(超文本传输协议)
ldap:389,轻量级目录访问协议 (LDAP)
HTTPS：443,安全套接字层（SSL 或 HTTPS）
microsoft-ds:445,Microsoft SMB 域服务器
smtp（旧版）:465,用于“邮件”的信息提交（经过认证的 SMTP）
printer:515,行式打印机 (LPR)、行式打印机监控程序 (LPD)
afpovertcp:548,通过 TCP 的 Apple 档案分享协议 (AFP)
rtsp:554,实时流协议 (RTSP)
submission:587,用于“邮件”的信息提交（经过认证的 SMTP）
ipp:631,互联网打印协议 (IPP)
ldaps:636,安全 LDAP
kerberos-adm:749,Kerberos 5 admin/changepw
imaps:993,邮件 IMAP SSL
pop3s:995,邮件 POP SSL

[UDP]协议常见端口：
DNS： 端口号：53。域名系统。
NTP: 123 网络时间协议 (NTP)
netbios-ns:137 Windows 互联网名称服务 (WINS)
netbios-dgm:138 NETBIOS 数据报服务
SNMP：端口号：162，管理端的默认端口，主要用来接收Agent的消息如TRAP告警消息。端口号：161，代理端(agent)的默认端口，接收管理端下发的消息如SET/GET指令等。简单网络管理协议。 主要用在局域网中对设备进行管理，应用最为广泛的是对路由器交换机等网络设备的管理，当然不仅限于网络设备。SNMP分为管理端和代理端(agent)。
osu-nms:192,OSU 网络监控系统
TFTP：端口号：69。简单文件传输协议。 用来在客户机与服务器之间进行简单文件传输的协议，提供不复杂、开销不大的文件传输服务。
DHCP：67
IKEv2:500,Wi-Fi 通话
rtsp:554,实时流协议 (RTSP)
kerberos-adm:749,Kerberos 5 admin/changepw
"""


def find_lan_ip(pkts):
    """
    找出一个数据包的源IP地址 原理用头10个流检测每个流都有的IP 该函数适应的场景有限，需要改进
    :param pkts:
    :return:
    """
    try:
        lan_ip = pkts[0]['IP'].src  # 注意：第一个流可能是ARP，则没有IP层
        other_ip = pkts[0]['IP'].dst
        count_a = 0
        count_b = 0
        
    except IndexError as e:  # ARP的情况 lan_ip
        if "Layer ['IP'] not found" in e.args:
            # print('ok')
            lan_ip = pkts[0]['ARP'].pdst
            return lan_ip
        else:
            return None
    for i in range(10):
        try:
            src_ip = pkts[i]['IP'].src
            dst_ip = pkts[i]['IP'].dst
            if lan_ip == src_ip or lan_ip == dst_ip:
                count_a += 1
            elif other_ip == src_ip or other_ip == dst_ip:
                count_b += 1
            else:
                print('找不到源IP，该流可能是ARP流')
                logger.info('找不到源IP，该流可能是ARP流')
        except IndexError as e:  # ARP的情况 lan_ip
            if "Layer ['IP'] not found" in e.args:
                # print('ok')
                lan_ip = pkts[i]['ARP'].pdst
                return lan_ip
            else:
                return None 
    if count_a == 10 or int(count_a-count_b) > 0:
        lan_ip = lan_ip
        print(f'本包的源IP是{lan_ip}')
        logger.info(f'本包的源IP是{lan_ip}')
        return lan_ip
    elif count_b == 10 or int(count_b-count_a) > 0:
        lan_ip = other_ip
        print(f'本包的源IP是{lan_ip}')
        logger.info(f'本包的源IP是{lan_ip}')
        return lan_ip
    else:
        print('找不到源IP')
        logger.info('找不到源IP')
        return None


def find_pcap(files):
    """
    从文件中找出pcap数据包格式文件
    :param files:
    :return:list
    """
    pcap_mode = '(.*?).p?cap(ng)?$'
    all_pcap = []
    for file in files:
        if not os.path.isdir(file):
            pcap_find = re.match(pcap_mode, file)
            if pcap_find:
                all_pcap.append(file)
    return all_pcap


def hex2visible_str(hex_string):
    hex_list = []
    ret_hex = ''
    while len(hex_string):
        hex_list.append(hex_string[0:2])
        hex_string = hex_string[2:]
    for i in hex_list:
        if ('a' in i[1] or 'b' in i[1] or 'c' in i[1] or 'd' in i[1] or 'e' in i[1] or 'f' in i[1]) \
                and i[0] not in 'abcdef':
            if i[0].isdigit():
                if 2 <= int(i[0]) <= 7:
                    if int(i[0]) == 7 and i[1] == 'f':
                        ret_hex += '.'
                    else:
                        ret_hex += unquote('%'+i)
                else:
                    ret_hex += '.'
            else:
                ret_hex += '.'
        else:
            if i[0].isdigit():
                if 0x20 <= int(int(i[0])*16+int(i[1])) <= 0x7e:
                    # print(unquote('%'+i))
                    ret_hex += unquote('%'+i)
                else:
                    ret_hex += '.'
            else:
                ret_hex += '.'
    return ret_hex


if __name__ == '__main__':
    all_pcap = find_pcap(files)
    
    other_ip_proto = {}
    for pcap in all_pcap:
        ALL_SSL = []
        ALL_TCP = []
        ALL_DNS_NAME = []
        ALL_HOST = []
        ALL_REFERER = []
        ALL_UA = []
        ALL_ORIGIN = []
        flow_list = []
        ALL_Other_Data = []
        five_tuple_dicts = {}  # 用于统计每个五元组出现次数

        pkts_json_name = pcap.split('cap')[-2].split('.')[-2]+'.json'
        pkts_txt_name = pcap.split('cap')[-2].split('.')[-2]+'.txt'

        print(f'\n分析 {pcap} ing!!!')
        logger.info(f'\n分析 {pcap} ing!!!')
        try:
            pkts = rdpcap(pcap)
            src_ip = find_lan_ip(pkts)  # 找出一个数据包中的局域网源IP
            if src_ip and src_ip not in src_host_list:
                src_host_list.append(src_ip)
            elif src_ip and src_ip in src_host_list:
                pass
            else:
                print('未发现有效源IP，异常退出，请老大检查您的函数！')
                logger.info('未发现有效源IP，异常退出，请老大检查您的函数！')
                time.sleep(5)
                quit()
            # pkts_json=open(pkts_json_name,'w')
            pkts_txt = open(pkts_txt_name, 'w', encoding='utf-8')
            """linux下通过tcpdump命令抓的包通常数据链路层不是Ethernet,而是cooked linux"""
            # print(len(pkts))# test1.pcapng 在wireshark中的No. 为1-5286 此处len(pkts)也为5286，吻合
            # print(pkts[1]['IP'].src)#源地址IP
            # print(pkts[1]['IP'].sport)#源端口
            # print(pkts[1]['IP'].dst)#目的地址IP
            # print(pkts[1]['IP'].dport)#目的端口
            # break

            # print(repr(pkts[0].show()))#TCP的案例
            # print(pkts[0]['Ethernet'].type)
            # pkts[pktno]['TLS Client Hello'].version#771==TLSv1.2
            # print('分割------------------')
            # print(repr(pkts[-2].show()))#ARP的案例
            # print(pkts[-2]['Ethernet'].type)
            # print(pkts[18]['IP'].proto)#UDP的案例
            # print(repr(pkts[18].show()))
            # print(pkts[18]['DNS'].an.rdata)#list
            # print(type(pkts[18]['DNS'].an))
            # print(str(pkts[18]['DNS'].an
            #   [0]['DNS Resource Record'].rrname))
            # print(json.loads(str(pkts[18]['DNS'].an[0]['DNS Resource Record'].rrname))['nm'])

            # for each_r in pkts[18]['DNS'].an.rdata:
            #   if 'name' in each_r.decode('utf-8'):
            #       print(each_r.decode('utf-8'))

            # print(repr(pkts[30].show()))
            # print(pkts[30]['ARP'].psrc)#疑似局域网网关
            # print(pkts[30]['ARP'].pdst)#疑似要查询的设备IP

            for pktno in range(len(pkts)):
                try:
                    if 'IP' not in pkts[pktno] and 'ARP' in pkts[pktno]:
                        pass
                        # print(f'第{pktno+1}个流 ARP')  # 抓包在链路层有时候会抓到ARP，没有五元组信息
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 0:
                        print(f'第{pktno+1}个流 HOPOPT')  # IPv6逐跳选项
                        logger.info(f'第{pktno+1}个流 HOPOPT')
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 1:
                        pass
                        # five_tuple='{}->{} {}'.format(pkts[pktno]['IP'].src,
                        # pkts[pktno]['IP'].dst,
                        # pkts[pktno]['IP'].proto)
                        # print(five_tuple)
                        # print(f'第{pktno+1}个流 ICMP')#互联网控制消息协议（ICMP）
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 2:
                        pass
                        # print(f'第{pktno+1}个流 IGMP')#因特网组管理协议（IGMP）
                        # print('{} {} {}'.format(pkts[pktno]['IP'].src,
                        # pkts[pktno]['IP'].dst,
                        # pkts[pktno]['IP'].proto))
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 3:
                        print(f'第{pktno+1}个流 GGP')  # 网关对网关协议
                        logger.info(f'第{pktno+1}个流 GGP')
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 4:
                        print(f'第{pktno+1}个流 IPv4')  # IPv4 (封装) / IP-within-IP 封装协议（IPIP）
                        logger.info(f'第{pktno+1}个流 IPv4')
                        five_tuple = f'{pkts[pktno]["IP"].src}:{pkts[pktno]["IP"].sport}->\
                         {pkts[pktno]["IP"].dst}:{pkts[pktno]["IP"].dport} {pkts[pktno]["IP"].proto}'
                        flow_list.append(five_tuple)
                        # print(five_tuple)
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 5:
                        print(f'第{pktno+1}个流 ST')  # 因特网流协议
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 6:  #################TCP################
                        # print(f'第{pktno+1}个流 TCP')#传输控制协议（TCP）
                        five_tuple = f'{pkts[pktno]["IP"].src}:{pkts[pktno]["IP"].sport}->\
                        {pkts[pktno]["IP"].dst}:{pkts[pktno]["IP"].dport} {"TCP"}'
                        # 'TCP'==pkts[pktno]['IP'].proto
                        flow_list.append(five_tuple)
                        # print(five_tuple)
                        # print(pkts[pktno].show())
                        # print(pkts[pktno]['TCP'].flags)
                        # break
                        if pkts[pktno]['IP'].dport == 80 and 'Raw' in pkts[pktno]:
                            # print(f'第{pktno+1}个流 TCP')  # 传输控制协议（TCP）
                            http_content = pkts[pktno]['Raw'].load
                            http_content_hex = pkts[pktno]['Raw'].load.hex()
                            visible_ascii = hex2visible_str(http_content_hex)
                            # print(visible_ascii)
                            if visible_ascii[:3] == 'GET' or visible_ascii[:3] == 'PUT' \
                                    or visible_ascii[:4] == 'POST' or visible_ascii[:4] == 'HEAD' \
                                    or visible_ascii[:7] == 'OPTIONS':
                                if visible_ascii[:3] == 'GET':
                                    if visible_ascii not in ALL_TCP:
                                        print(f'第{pktno+1}个流 HTTP/GET')
                                        # print(pkts[pktno]['TCP'].flags)
                                        # print(http_content_hex+'\n')
                                        # print(http_content_hex.split('0d0a'))
                                        # break
                                        ALL_TCP.append(visible_ascii)
                                        pkts_txt.write(f'\n[{pktno+1}] \
                                        {five_tuple.replace("TCP","HTTP/GET")}:\n{visible_ascii}\n')
                                    else:
                                        pass
                                elif visible_ascii[:3] == 'PUT':
                                    if visible_ascii not in ALL_TCP:
                                        print(f'第{pktno+1}个流 HTTP/PUT')
                                        ALL_TCP.append(visible_ascii)
                                        pkts_txt.write(f'\n[{pktno+1}] \
                                        {five_tuple.replace("TCP","HTTP/PUT")}:\n{visible_ascii}\n')
                                    else:
                                        pass
                                elif visible_ascii[:4] == 'POST':
                                    if visible_ascii not in ALL_TCP:
                                        print(f'第{pktno+1}个流 HTTP/POST') 
                                        print(pkts[pktno]['TCP'].flags)
                                        ALL_TCP.append(visible_ascii)
                                        pkts_txt.write(f'\n[{pktno+1}] \
                                        {five_tuple.replace("TCP","HTTP/POST")}:\n{visible_ascii}\n')
                                    else:
                                        pass
                                elif visible_ascii[:4] == 'HEAD':
                                    if visible_ascii not in ALL_TCP:
                                        print(f'第{pktno+1}个流 HTTP/HEAD')
                                        ALL_TCP.append(visible_ascii)
                                        pkts_txt.write(f'\n[{pktno+1}] \
                                        {five_tuple.replace("TCP","HTTP/HEAD")}:\n{visible_ascii}\n')
                                    else:
                                        pass
                                elif visible_ascii[:7] == 'OPTIONS':
                                    if visible_ascii not in ALL_TCP:
                                        print(f'第{pktno+1}个流 HTTP/OPTIONS') 
                                        ALL_TCP.append(visible_ascii)
                                        pkts_txt.write(f'\n[{pktno+1}] \
                                        {five_tuple.replace("TCP","HTTP/OPTIONS")}:\n{visible_ascii}\n')
                                    else:
                                        pass
                                else:
                                    pass
                            else:
                                print(f"第{pktno+1}个流 解密但其他")
                                print(pkts[pktno]['TCP'].flags)
                                pass
                            # byte_array=bytearray.fromhex(http_content_hex)
                            # print(byte_array.decode('hex'))
                            # print(codecs.decode(http_content_hex,'hex')) m
                        elif pkts[pktno]['IP'].dport == 443 and \
                                pkts[pktno]['IP'].src in src_host_list and \
                                'TLS Servername' in pkts[pktno]:
                            ssl_name = pkts[pktno]['TLS Servername'].data
                            ssl_name_print = ssl_name.decode()
                            if ssl_name_print not in ALL_SSL: 
                                print(f'第{pktno+1}个流 TCP SSL')  # 传输控制协议（TCP）
                                print(ssl_name_print)
                                print(ssl_name.hex())
                                ALL_SSL.append(ssl_name_print)
                                pkts_txt.write(f'\n[{pktno+1}] \
                                {five_tuple.replace("TCP","SSL")}:\n\
                                {ssl_name_print}\n\
                                {ssl_name.hex()}\n')
                        elif pkts[pktno]['IP'].dport == 443 and 'SSL/TLS' in pkts[pktno] \
                                and pkts[pktno]['IP'].src in src_host_list \
                                and 'Raw' in pkts[pktno] \
                                and 'TLS Handshakes' not in pkts[pktno]:
                            print(f'第{pktno+1}个流 TCP SSL_Encrypted_Data')
                            encrypted_application_data = pkts[pktno]['Raw'].load
                            encrypted_application_data_hex = pkts[pktno]['Raw'].load.hex()
                            # print(encrypted_application_data_hex)
                        elif pkts[pktno]['IP'].dport == 20 and pkts[pktno]['IP'].src in src_host_list:
                            print(f'第{pktno+1}个流 FTP[Data]')
                        elif pkts[pktno]['IP'].dport == 21 and pkts[pktno]['IP'].src in src_host_list:
                            print(f'第{pktno+1}个流 FTP[Control]')
                        elif pkts[pktno]['IP'].dport == 22 and pkts[pktno]['IP'].src in src_host_list:
                            print(f'第{pktno+1}个流 SSH')
                        elif pkts[pktno]['IP'].dport == 23 and pkts[pktno]['IP'].src in src_host_list:
                            print(f'第{pktno+1}个流 Telnet')
                        elif pkts[pktno]['IP'].dport == 25 and pkts[pktno]['IP'].src in src_host_list:
                            print(f'第{pktno+1}个流 SMTP')
                        elif pkts[pktno]['IP'].dport == 67 and pkts[pktno]['IP'].src in src_host_list:
                            print(f'第{pktno+1}个流 DHCP')
                        elif pkts[pktno]['IP'].dport == 69 and pkts[pktno]['IP'].src in src_host_list:
                            print(f'第{pktno+1}个流 TFTP')
                        elif pkts[pktno]['IP'].dport == 110 and pkts[pktno]['IP'].src in src_host_list:
                            print(f'第{pktno+1}个流 POP3')
                        elif pkts[pktno]['IP'].dport == 143 and pkts[pktno]['IP'].src in src_host_list:
                            print(f'第{pktno+1}个流 IMAP4')
                        elif pkts[pktno]['IP'].dport == 443 \
                                and pkts[pktno]['IP'].src in src_host_list \
                                and 'SSL/TLS' in pkts[pktno] \
                                and 'TLS Record' in pkts[pktno] \
                                and 'TLS Handshakes' in pkts[pktno] \
                                and pkts[pktno].records[0]['TLS Record'].version == 771:
                            print(f'第{pktno+1}个流 TCP SSL/TLSv1.2')
                            # ssl_show=pkts[pktno].show()
                            # encrypted_application_data = pkts[pktno]['SSL/TLS'].records[0]['TLS Record'].version#['TLS Ciphertext'].data.hex()
                            # print(encrypted_application_data)
                            # print(ssl_data)
                            # visible_ascii=hex2visible_str(encrypted_application_data)
                            # print(visible_ascii)
                            # break
                        elif pkts[pktno]['IP'].dport == 5223 \
                                and pkts[pktno]['IP'].src in src_host_list \
                                and pkts[pktno]['TCP'].flags == 'PA' \
                                and 'Raw' in pkts[pktno] \
                                and 'courier.push.apple.com' in str(pkts[pktno]['Raw'].load):
                            print(f'第{pktno+1}个流 Apple推送通知服务')
                        elif pkts[pktno]['IP'].dport == 8081 \
                                and pkts[pktno]['TCP'].flags == 'PA' \
                                and 'Raw' in pkts[pktno] \
                                and 'bea_key' in str(pkts[pktno]['Raw'].load):
                            pass
                        else:
                            if pkts[pktno]['TCP'].flags == 'PA' \
                                    and pkts[pktno]['IP'].src in src_host_list \
                                    and 'Raw' in pkts[pktno] \
                                    and pkts[pktno]['Raw'].load.hex() not in ALL_Other_Data:
                                print(f"第{pktno+1}个流 TCP 端口:{pkts[pktno]['IP'].dport}")
                                # print(pkts[pktno]['TCP'].flags)
                                # print(pkts[pktno].show())
                                print(pkts[pktno]['Raw'].load.hex())  # .hex()
                                ALL_Other_Data.append(pkts[pktno]['Raw'].load.hex())
                                print(hex2visible_str(pkts[pktno]['Raw'].load.hex()))
                                # break
                            else:
                                pass
                        # break
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 7:
                        print(f'第{pktno+1}个流 CBT')  # 有核树组播路由协议
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 8:
                        print(f'第{pktno+1}个流 EGP')  # 外部网关协议
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 9:
                        print(f'第{pktno+1}个流 IGP')  # 内部网关协议（任意私有内部网关（用于思科的IGRP））
                    # elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==10:
                    #   print(f'第{pktno+1}个流 BBN-RCC-MON')#BBN RCC 监视
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 11:
                        print(f'第{pktno+1}个流 NVP-II')  # 网络语音协议
                    # elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==12:
                    #   print(f'第{pktno+1}个流 PUP')#Xerox PUP（英语：帕罗奥多通用报文）
                    # elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==13:
                    #   print(f'第{pktno+1}个流 ARGUS')#ARGUS
                    # elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==14:
                    #   print(f'第{pktno+1}个流 EMCON')#EMCON
                    # elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==15:
                    #   print(f'第{pktno+1}个流 XNET')#Cross Net Debugger
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 16:
                        print(f'第{pktno+1}个流 CHAOS')  # CHAOS
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 17:
                        five_tuple = f'{pkts[pktno]["IP"].src}:{pkts[pktno]["IP"].sport}\
                        ->{pkts[pktno]["IP"].dst}:{pkts[pktno]["IP"].dport} {"UDP"}'
                        # pkts[pktno]['IP'].proto
                        flow_list.append(five_tuple)
                        if pkts[pktno]['UDP'].dport == 53 and pkts[pktno]['IP'].src in src_host_list:
                            try:
                                dnsname = pkts[pktno]['DNSQR'].qname
                                dns_name_print = '.'+dnsname.decode()
                                if dns_name_print not in ALL_DNS_NAME:
                                    print(f'第{pktno+1}个流 DNS')
                                    print(dns_name_print)
                                    # dns_hex_list=[str(hex(int(len(i)/2))[2:])+i for i in dnsname.hex().split('2e') if i]
                                    dns_hex_list = ["%02x" % int(len(i)/2)+i for i in dnsname.hex().split('2e') if i]
                                    dns_name_hex_print = ' '.join(dns_hex_list)+' 00'
                                    print(dns_name_hex_print)
                                    ALL_DNS_NAME.append(dns_name_print)
                                    pkts_txt.write(f'\n[{pktno+1}] \
                                    {five_tuple.replace("UDP","DNS")}:\n\
                                    {dns_name_print}\n\
                                    {dns_name_hex_print}\n')
                            except IndexError:
                                pass
                        elif pkts[pktno]['UDP'].dport == 67 and pkts[pktno]['IP'].src in src_host_list:
                            print(f'第{pktno+1}个流 DHCP')
                        elif pkts[pktno]['UDP'].dport == 69 and pkts[pktno]['IP'].src in src_host_list:
                            print(f'第{pktno+1}个流 TFTP')
                        elif pkts[pktno]['UDP'].dport == 161 and pkts[pktno]['IP'].src in src_host_list:
                            print(f'第{pktno+1}个流 SNMP[agent]')
                        elif pkts[pktno]['UDP'].dport == 162 and pkts[pktno]['IP'].src in src_host_list:
                            print(f'第{pktno+1}个流 SNMP[manage]')
                        else:
                            pass
                        # print(five_tuple)
                        # print(f'第{pktno+1}个流 UDP')  # 用户数据报协议（UDP）
                        # print('{}:{} {}:{} {}'.format(pkts[pktno]['IP'].src,
                        # pkts[pktno]['IP'].sport,
                        # pkts[pktno]['IP'].dst,
                        # pkts[pktno]['IP'].dport,
                        # pkts[pktno]['IP'].proto))
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 18:
                        print(f'第{pktno+1}个流 MUX')  # 多路复用
                    # elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==19:
                    #   print(f'第{pktno+1}个流 DCN-MEAS')#DCN Measurement Subsystems
                    # elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==20:
                    #   print(f'第{pktno+1}个流 HMP')#Host Monitoring Protocol
                    # elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==21:
                    #   print(f'第{pktno+1}个流 PRM')#Packet Radio Measurement
                    # elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==22:
                    #   print(f'第{pktno+1}个流 XNS-IDP')#XEROX NS IDP
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 23:
                        print(f'第{pktno+1}个流 TRUNK-1')  # TRUNK-1
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 24:
                        print(f'第{pktno+1}个流 TRUNK-2')  # TRUNK-2
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 25:
                        print(f'第{pktno+1}个流 LEAF-1')  # LEAF-1
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 26:
                        print(f'第{pktno+1}个流 LEAF-2')  # LEAF-2
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 27:
                        print(f'第{pktno+1}个流 RDP')  # 可靠数据协议（英语：Reliable Data Protocol）
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 28:
                        print(f'第{pktno+1}个流 IRTP')  # Internet Reliable Transaction Protocol
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 29:
                        print(f'第{pktno+1}个流 ISO-TP4')  # ISO Transport Protocol Class 4
                    # elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==30:
                    #   print(f'第{pktno+1}个流 NETBLT')#Bulk Data Transfer Protocol
                    # elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==31:
                    #   print(f'第{pktno+1}个流 MFE-NSP')#MFE Network Services Protocol
                    # elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==32:
                    #   print(f'第{pktno+1}个流 MERIT-INP')#MERIT Internodal Protocol
                    # elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==33:
                    #   print(f'第{pktno+1}个流 DCCP')#Datagram Congestion Control Protocol
                    # elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==34:
                    #   print(f'第{pktno+1}个流 3PC')#Third Party Connect Protocol
                    # elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==35:
                    #   print(f'第{pktno+1}个流 IDPR')#Inter-Domain Policy Routing Protocol
                    # elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==36:
                    #   print(f'第{pktno+1}个流 XTP')#Xpress Transport Protocol
                    # elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==37:
                    #   print(f'第{pktno+1}个流 DDP')#Datagram Delivery Protocol
                    # elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==38:
                    #   print(f'第{pktno+1}个流 IDPR-CMTP')#IDPR Control Message Transport Protocol
                    # elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==39:
                    #   print(f'第{pktno+1}个流 TP++')#TP++ Transport Protocol
                    # elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==40:
                    #   print(f'第{pktno+1}个流 IL')#IL Transport Protocol
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 41:
                        print(f'第{pktno+1}个流 IPv6')  # IPv6 封装
                        five_tuple = f'{pkts[pktno]["IP"].src}:{pkts[pktno]["IP"].sport}->\
                        {pkts[pktno]["IP"].dst}:{pkts[pktno]["IP"].dport} {pkts[pktno]["IP"].proto}'
                        flow_list.append(five_tuple)
                        # print(five_tuple)
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 42:
                        print(f'第{pktno+1}个流 SDRP')  # Source Demand Routing Protocol
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 43:
                        print(f'第{pktno+1}个流 IPv6-Route')  # IPv6路由拓展头
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 44:
                        print(f'第{pktno+1}个流 IPv6-Frag')  # IPv6分片扩展头
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 45:
                        print(f'第{pktno+1}个流 IDRP')  # Inter-Domain Routing Protocol
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 46:
                        print(f'第{pktno+1}个流 RSVP')  # 资源预留协议
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 47:
                        print(f'第{pktno+1}个流 GRE')  # 通用路由封装（GRE）
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 48:
                        print(f'第{pktno+1}个流 DSR')  # 动态源路由（英语：Dynamic Source Routing）
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 49:
                        print(f'第{pktno+1}个流 BNA')  # BNA
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 50:
                        print(f'第{pktno+1}个流 ESP')  # 封装安全协议（ESP）
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 51:
                        print(f'第{pktno+1}个流 AH')  # 认证头协议（AH）
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 56:
                        print(f'第{pktno+1}个流 TLSP')  # 传输层安全性协议（使用Kryptonet密钥管理）
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 58:
                        print(f'第{pktno+1}个流 IPv6-ICMP')  # 互联网控制消息协议第六版（ICMPv6）
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 59:
                        print(f'第{pktno+1}个流 IPv6-NoNxt')  # IPv6无负载头
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 60:
                        print(f'第{pktno+1}个流 IPv6-Opts')  # #IPv6目标选项扩展头
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 88:
                        print(f'第{pktno+1}个流 EIGRP')  # 增强型内部网关路由协议（EIGRP）
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 89:
                        print(f'第{pktno+1}个流 OSPF')  # 开放式最短路径优先（OSPF）
                        five_tuple = f'{pkts[pktno]["IP"].src}:{pkts[pktno]["IP"].sport}->\
                        {pkts[pktno]["IP"].dst}:{pkts[pktno]["IP"].dport} {pkts[pktno]["IP"].proto}'
                        flow_list.append(five_tuple)
                        # print(five_tuple)
                    elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto == 115:
                        print(f'第{pktno+1}个流 L2TP')  # 第二层隧道协议第三版
                    else:
                        if pkts[pktno]['IP'].proto not in other_ip_proto:
                            # other_ip_proto.append(pkts[pktno]['IP'].proto)
                            other_ip_proto[pktno+1] = pkts[pktno]['IP'].proto
                            print(f'第{pktno+1}个流 新IP proto！！！')
                        else:
                            pass
                    # print(str(pkts[pktno]).replace('\\x','.'))
                    # print(repr(pkts[pktno].show()))
                    # print(pkts[pktno]['Ethernet'].type)#2048==IPv4/2054==ARP/
                    # print(pkts[pktno]['Ethernet'].src)#源地址MAC
                    # print(pkts[pktno]['Ethernet'].dst)#目的地址MAC/全为ff时是局域网广播Broadcast-ARP
                    # print(pkts[pktno]['IP'].src)#源地址IP
                    # print(pkts[pktno]['IP'].dst)#目的地址IP
                    # print(pkts[pktno]['IP'].proto)#6==TCP/17==UDP/1==ICMP
                    # break
                except RuntimeError:
                    traceback.print_exc()
                    logger.info(traceback.format_exc())
                except IndexError:
                    print(f'第{pktno+1}个:{traceback.format_exc()}')
        except scapy.error.Scapy_Exception:
            print(f'Warning：No data could be read!!!\n数据包格式有误{traceback.format_exc()}')

        print(f'新出现的IP proto：\n{other_ip_proto}')
        # i=0
        # for item in flow_list:
        #     if flow_list.count(item)>=1:
        #         five_tuple_dicts[item]=flow_list.count(item) #统计五元组重复次数
        #         i = i+1
        #     if i%1000==0:#每1000次打印一下进度
        #         print('字典处理进度:',i/len(flow_list)*100,'%')
        
        # print(five_tuple_dicts)
        print("\n本包的Host有：")
        pkts_txt.write("\n本包的Host有：\n")
        for host in ALL_HOST:
            print(host)
            pkts_txt.write(f"Host:{host}\n")
        print(f"\n本包的Origin有：")
        pkts_txt.write(f"\n本包的Origin有：\n")
        for origin in ALL_ORIGIN:
            print(origin)
            pkts_txt.write(f":{origin}\n")
        print(f"\n本包的Referer有：")
        pkts_txt.write(f"\n本包的Referer有：\n")
        for referer in ALL_REFERER:
            print(referer)
            pkts_txt.write(f":{referer}\n")
        print(f"\n本包的UA有：")
        pkts_txt.write(f"\n本包的UA有：\n")
        for ua in ALL_UA:
            print(ua)
            pkts_txt.write(f":{ua}\n")
        print(f"\n本包的SSL_NANE有：")
        pkts_txt.write(f"\n本包的SSL_NANE有：\n")
        for ssl in ALL_SSL:
            print(ssl)
            pkts_txt.write(f"{ssl}\n")
        print(f"\n本包的DNS_NAME有：")
        pkts_txt.write(f"\n本包的DNS_NAME有：\n")
        for dns in ALL_DNS_NAME:
            print(dns)
            pkts_txt.write(f"{dns}\n")

        pkts_txt.close()

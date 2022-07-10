#！-*-coding:utf-8-*- 此脚本尽量用python3写成
import logging
logging.captureWarnings(True)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)#此一句去掉命令行中的WARNING:
from scapy.all import *
from scapy_ssl_tls.ssl_tls import *
import re,os,shutil,sys,json
from urllib.parse import quote,unquote
# import codecs

"""
端口范围：0~65535，
公认端口（System Ports）：0~1023是被RFC 3232规定好的，用于特定协议；
注册端口（User Ports）：1024-49151，使用这类端口号必须在IANA按照规定登记，以防止重复；
动态/私有端口（Dynamic and/or Private Ports）：49152-65535，被操作系统动态分配；
"""

def find_LAN_IP(pkts):#找出一个数据包的源IP地址 原理用头10个流检测每个流都有的IP
	LAN_IP=pkts[0]['IP'].src#注意：第一个流可能是ARP，则没有IP层
	OTHER_IP=pkts[0]['IP'].dst
	count_a=0
	count_b=0
	for i in range(10):
		SRC_IP=pkts[i]['IP'].src
		DST_IP=pkts[i]['IP'].dst
		if LAN_IP==SRC_IP or LAN_IP==DST_IP:
			count_a+=1
		elif OTHER_IP==SRC_IP or OTHER_IP==DST_IP:
			count_b+=1
		else:
			print('找不到源IP，该流可能是ARP流')
	if count_a==10 or int(count_a-count_b)>0:
		LAN_IP=LAN_IP
		print(f'本包的源IP是{LAN_IP}')
		return LAN_IP
	elif count_b==10 or int(count_b-count_a)>0:
		LAN_IP=OTHER_IP
		print(f'本包的源IP是{LAN_IP}')
		return LAN_IP
	else:
		print('找不到源IP')
		return None
	
def find_pcap(files):
	pcap_mode='(.*?).p?cap(ng)?$'
	all_pcap=[]
	for file in files:
		if not os.path.isdir(file):
			pcap_find=re.match(pcap_mode,file)
			if pcap_find:
				all_pcap.append(file)
	return all_pcap

def hex2visible_str(hex_string):
	hex_list=[]
	ret_hex=''
	while(len(hex_string)):
		hex_list.append(hex_string[0:2])
		hex_string=hex_string[2:]
	for i in hex_list:
		if ('a' in i[1] or 'b' in i[1] or 'c' in i[1] or 'd' in i[1] or 'e' in i[1] or 'f' in i[1]) and i[0] not in 'abcdef':
			if i[0].isdigit():
				if  2<=int(i[0])<=7:
					ret_hex+=unquote('%'+i)
				else:
					ret_hex+='.'
			else:
				ret_hex+='.'
		else:
			if i[0].isdigit():
				if 0x20<=int(int(i[0])*16+int(i[1])) <=0x7e:
					# print(unquote('%'+i))
					ret_hex+=unquote('%'+i)
				else:
					ret_hex+='.'
			else:
				ret_hex+='.'
	return ret_hex

if __name__ == '__main__':
	src_host_list=[]
	dst_sslon_port_list=['80','8080','808']#这几个端口的数据流很可能是解密的
	dst_ssloff_port_list=['443']#这几个端口的数据流很可能是加密的

	CURRENT_PATH=os.path.abspath('')
	wait_analysed_path=CURRENT_PATH
	if 'ANALYZED_PCAP' not in os.listdir(wait_analysed_path):
		os.mkdir(os.path.join(CURRENT_PATH,'ANALYZED_PCAP'))
	else:
		pass
	analysed_path=os.path.join(CURRENT_PATH,'ANALYZED_PCAP')
	files=os.listdir(wait_analysed_path)
	all_pcap=find_pcap(files)
	
	other_ip_proto={}
	for pcap in all_pcap:
		ALL_SSL=[]
		ALL_DNS_NAME=[]
		ALL_HOST=[]
		ALL_REFERER=[]
		ALL_UA=[]
		ALL_ORIGIN=[]

		print (f'\n分析 {pcap} ing!!!')
		try:
			pkts=rdpcap(pcap)
			src_ip=find_LAN_IP(pkts)
			if src_ip and src_ip not in src_host_list:
				src_host_list.append(src_ip)
			elif src_ip and src_ip in src_host_list:
				pass
			else:
				print('未发现有效源IP，异常退出，请老大检查您的函数！')
				time.sleep(10)
				quit()

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
			# 	[0]['DNS Resource Record'].rrname))
			# print(json.loads(str(pkts[18]['DNS'].an[0]['DNS Resource Record'].rrname))['nm'])

			# for each_r in pkts[18]['DNS'].an.rdata:
			# 	if 'name' in each_r.decode('utf-8'):
			# 		print(each_r.decode('utf-8'))

			# print(repr(pkts[30].show()))
			# print(pkts[30]['ARP'].psrc)#疑似局域网网关
			# print(pkts[30]['ARP'].pdst)#疑似要查询的设备IP

			# #找出一个数据包中的局域网源IP


			for pktno in range(len(pkts)):
				try:
					if 'IP' not in pkts[pktno] and 'ARP' in pkts[pktno]:
						print(f'第{pktno+1}个流 ARP')#抓包在链路层有时候会抓到ARP，没有五元组信息
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==0:
						print(f'第{pktno+1}个流 HOPOPT')#IPv6逐跳选项
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==1:
						pass
						# print(f'第{pktno+1}个流 ICMP')#互联网控制消息协议（ICMP）
						# print('{}:{} {}:{} {}'.format(pkts[pktno]['IP'].src,pkts[pktno]['IP'].sport,pkts[pktno]['IP'].dst,pkts[pktno]['IP'].dport,pkts[pktno]['IP'].proto))
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==2:
						pass
						# print(f'第{pktno+1}个流 IGMP')#因特网组管理协议（IGMP）
						# print('{} {} {}'.format(pkts[pktno]['IP'].src,pkts[pktno]['IP'].dst,pkts[pktno]['IP'].proto))
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==3:
						print(f'第{pktno+1}个流 GGP')#网关对网关协议
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==4:
						print(f'第{pktno+1}个流 IPv4')#IPv4 (封装) / IP-within-IP 封装协议（IPIP）
						print('{}:{} {}:{} {}'.format(pkts[pktno]['IP'].src,pkts[pktno]['IP'].sport,pkts[pktno]['IP'].dst,pkts[pktno]['IP'].dport,pkts[pktno]['IP'].proto))
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==5:
						print(f'第{pktno+1}个流 ST')#因特网流协议
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==6:
						# print(f'第{pktno+1}个流 TCP')#传输控制协议（TCP）
						# print('{}:{} {}:{} {}'.format(pkts[pktno]['IP'].src,pkts[pktno]['IP'].sport,pkts[pktno]['IP'].dst,pkts[pktno]['IP'].dport,pkts[pktno]['IP'].proto))
						if pkts[pktno]['IP'].dport==80 and 'Raw' in pkts[pktno]:
							print(f'第{pktno+1}个流 TCP')#传输控制协议（TCP）
							http_content=pkts[pktno]['Raw'].load
							http_content_hex=pkts[pktno]['Raw'].load.hex()#
							hex_format=hex2visible_str(http_content_hex)
							print(hex_format)
							# byte_array=bytearray.fromhex(http_content_hex)
							# print(byte_array.decode('hex'))
							# print(codecs.decode(http_content_hex,'hex')) m
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==7:
						print(f'第{pktno+1}个流 CBT')#有核树组播路由协议
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==8:
						print(f'第{pktno+1}个流 EGP')#外部网关协议
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==9:
						print(f'第{pktno+1}个流 IGP')#内部网关协议（任意私有内部网关（用于思科的IGRP））
					# elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==10:
					# 	print(f'第{pktno+1}个流 BBN-RCC-MON')#BBN RCC 监视
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==11:
						print(f'第{pktno+1}个流 NVP-II')#网络语音协议
					# elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==12:
					# 	print(f'第{pktno+1}个流 PUP')#Xerox PUP（英语：帕罗奥多通用报文）
					# elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==13:
					# 	print(f'第{pktno+1}个流 ARGUS')#ARGUS
					# elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==14:
					# 	print(f'第{pktno+1}个流 EMCON')#EMCON
					# elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==15:
					# 	print(f'第{pktno+1}个流 XNET')#Cross Net Debugger
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==16:
						print(f'第{pktno+1}个流 CHAOS')#CHAOS
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==17:
						pass
						# print(f'第{pktno+1}个流 UDP')#用户数据报协议（UDP）
						# print('{}:{} {}:{} {}'.format(pkts[pktno]['IP'].src,pkts[pktno]['IP'].sport,pkts[pktno]['IP'].dst,pkts[pktno]['IP'].dport,pkts[pktno]['IP'].proto))
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==18:
						print(f'第{pktno+1}个流 MUX')#多路复用
					# elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==19:
					# 	print(f'第{pktno+1}个流 DCN-MEAS')#DCN Measurement Subsystems
					# elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==20:
					# 	print(f'第{pktno+1}个流 HMP')#Host Monitoring Protocol
					# elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==21:
					# 	print(f'第{pktno+1}个流 PRM')#Packet Radio Measurement
					# elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==22:
					# 	print(f'第{pktno+1}个流 XNS-IDP')#XEROX NS IDP
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==23:
						print(f'第{pktno+1}个流 TRUNK-1')#TRUNK-1
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==24:
						print(f'第{pktno+1}个流 TRUNK-2')#TRUNK-2
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==25:
						print(f'第{pktno+1}个流 LEAF-1')#LEAF-1
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==26:
						print(f'第{pktno+1}个流 LEAF-2')#LEAF-2
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==27:
						print(f'第{pktno+1}个流 RDP')#可靠数据协议（英语：Reliable Data Protocol）
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==28:
						print(f'第{pktno+1}个流 IRTP')#Internet Reliable Transaction Protocol
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==29:
						print(f'第{pktno+1}个流 ISO-TP4')#ISO Transport Protocol Class 4
					# elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==30:
					# 	print(f'第{pktno+1}个流 NETBLT')#Bulk Data Transfer Protocol
					# elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==31:
					# 	print(f'第{pktno+1}个流 MFE-NSP')#MFE Network Services Protocol
					# elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==32:
					# 	print(f'第{pktno+1}个流 MERIT-INP')#MERIT Internodal Protocol
					# elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==33:
					# 	print(f'第{pktno+1}个流 DCCP')#Datagram Congestion Control Protocol
					# elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==34:
					# 	print(f'第{pktno+1}个流 3PC')#Third Party Connect Protocol
					# elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==35:
					# 	print(f'第{pktno+1}个流 IDPR')#Inter-Domain Policy Routing Protocol
					# elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==36:
					# 	print(f'第{pktno+1}个流 XTP')#Xpress Transport Protocol
					# elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==37:
					# 	print(f'第{pktno+1}个流 	DDP')#Datagram Delivery Protocol
					# elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==38:
					# 	print(f'第{pktno+1}个流 IDPR-CMTP')#IDPR Control Message Transport Protocol
					# elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==39:
					# 	print(f'第{pktno+1}个流 TP++')#TP++ Transport Protocol
					# elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==40:
					# 	print(f'第{pktno+1}个流 	IL')#IL Transport Protocol
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==41:
						print(f'第{pktno+1}个流 IPv6')#IPv6 封装
						print('{}:{} {}:{} {}'.format(pkts[pktno]['IP'].src,pkts[pktno]['IP'].sport,pkts[pktno]['IP'].dst,pkts[pktno]['IP'].dport,pkts[pktno]['IP'].proto))
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==42:
						print(f'第{pktno+1}个流 SDRP')#	Source Demand Routing Protocol
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==43:
						print(f'第{pktno+1}个流 IPv6-Route')#IPv6路由拓展头
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==44:
						print(f'第{pktno+1}个流 IPv6-Frag')#IPv6分片扩展头
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==45:
						print(f'第{pktno+1}个流 IDRP')#Inter-Domain Routing Protocol
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==46:
						print(f'第{pktno+1}个流 RSVP')#资源预留协议
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==47:
						print(f'第{pktno+1}个流 GRE')#通用路由封装（GRE）
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==48:
						print(f'第{pktno+1}个流 DSR')#动态源路由（英语：Dynamic Source Routing）
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==49:
						print(f'第{pktno+1}个流 BNA')#BNA
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==50:
						print(f'第{pktno+1}个流 ESP')#封装安全协议（ESP）
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==51:
						print(f'第{pktno+1}个流 AH')#认证头协议（AH）
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==56:
						print(f'第{pktno+1}个流 TLSP')#传输层安全性协议（使用Kryptonet密钥管理）
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==58:
						print(f'第{pktno+1}个流 IPv6-ICMP')#互联网控制消息协议第六版（ICMPv6）
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==59:
						print(f'第{pktno+1}个流 IPv6-NoNxt')#IPv6无负载头
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==60:
						print(f'第{pktno+1}个流 IPv6-Opts')##IPv6目标选项扩展头
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==88:
						print(f'第{pktno+1}个流 EIGRP')#	增强型内部网关路由协议（EIGRP）
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==89:
						print(f'第{pktno+1}个流 OSPF')#开放式最短路径优先（OSPF）
						print('{}:{} {}:{} {}'.format(pkts[pktno]['IP'].src,pkts[pktno]['IP'].sport,pkts[pktno]['IP'].dst,pkts[pktno]['IP'].dport,pkts[pktno]['IP'].proto))
					elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==115:
						print(f'第{pktno+1}个流 L2TP')#第二层隧道协议第三版
					else:
						if pkts[pktno]['IP'].proto not in other_ip_proto:
							# other_ip_proto.append(pkts[pktno]['IP'].proto)
							other_ip_proto[pktno+1]=pkts[pktno]['IP'].proto
							print(f'第{pktno+1}个流 新IP proto！！！')
					# print(str(pkts[pktno]).replace('\\x','.'))
					# print(repr(pkts[pktno].show()))
					# print(pkts[pktno]['Ethernet'].type)#2048==IPv4/2054==ARP/
					# print(pkts[pktno]['Ethernet'].src)#源地址MAC
					# print(pkts[pktno]['Ethernet'].dst)#目的地址MAC/全为ff时是局域网广播Broadcast-ARP
					# print(pkts[pktno]['IP'].src)#源地址IP
					# print(pkts[pktno]['IP'].dst)#目的地址IP
					# print(pkts[pktno]['IP'].proto)#6==TCP/17==UDP/1==ICMP
					# break
				except RuntimeError as e:
					print(e.args)
				except IndexError as e:#
					print(f'第{pktno+1}个:{e.args}')
		except scapy.error.Scapy_Exception as e:
			print('Warning：No data could be read!!!\n数据包格式有误')

		print(f'新出现的IP proto：\n{other_ip_proto}')
		break
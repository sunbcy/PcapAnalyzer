#！-*-coding:utf-8-*- 此脚本尽量用python3写成
import logging
logging.captureWarnings(True)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)#此一句去掉命令行中的WARNING:
from scapy.all import *
from scapy_ssl_tls.ssl_tls import *
import re,os,shutil,sys,json

# reload(sys)
# sys.setdefaultencoding('utf-8')
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

	pcap_mode='(.*?).p?cap(ng)?$'
	all_pcap=[]
	for file in files:
		if not os.path.isdir(file):
			pcap_find=re.match(pcap_mode,file)
			if pcap_find:
				all_pcap.append(file)

	other_ip_proto={}
	for pcap in all_pcap:
		ALL_SSL=[]
		ALL_DNS_NAME=[]
		ALL_HOST=[]
		ALL_REFERER=[]
		ALL_UA=[]
		ALL_ORIGIN=[]

		print (f'\n分析 {pcap} ing!!!')
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
		# print(pkts[1]['IP'].dst)#目的地址IP

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
					print(f'第{pktno+1}个流 ARP')
				elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==1:
					print(f'第{pktno+1}个流 ICMP')
				# elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==2:
				# 	print(f'第{pktno+1}个流 IGMP')
				elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==6:
					print(f'第{pktno+1}个流 TCP')
				elif 'IP' in pkts[pktno] and pkts[pktno]['IP'].proto==17:
					print(f'第{pktno+1}个流 UDP')
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
			except IndexError as e:
				print(f'第{pktno+1}个:{e.args}')

		print(f'新出现的IP proto：\n{other_ip_proto}')

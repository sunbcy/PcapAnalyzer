#-*-encoding:utf-8-*-
import logging
logging.captureWarnings(True)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy_ssl_tls.ssl_tls import *
import os
import re
import shutil

def find_pcaps(files):
    #通过re正则表达式找到pcap文件
    pcap_mode='(.*?).p?cap(ng)?$'
    all_pcap=[]
    for file in files:#遍历文件夹列表
       if not os.path.isdir(file):
           pcap_find=re.match(pcap_mode,file)
           if pcap_find:#在文件夹列表中发现了pcap文件后
               all_pcap.append(file)#将它的名字添加到 all_pcap 的列表里
    return all_pcap

if __name__=='__main__':
    CURRENT_PATH=os.path.abspath('')
    wait_analyse_path=CURRENT_PATH
    if 'ANALYZED_PCAP' not in os.listdir(CURRENT_PATH):
        os.mkdir('ANALYZED_PCAP')
    analysed_path=os.path.join(CURRENT_PATH,'ANALYZED_PCAP')
    print (os.listdir(CURRENT_PATH))
    files=os.listdir(wait_analyse_path)
    
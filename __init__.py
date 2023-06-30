import os

src_host_list = []
dst_sslon_port_list = ['80', '8080', '808']  # 这几个端口的数据流很可能是解密的
dst_ssloff_port_list = ['443']  # 这几个端口的数据流很可能是加密的

CURRENT_PATH = os.path.abspath('')
wait_analysed_path = CURRENT_PATH
if 'ANALYZED_PCAP' not in os.listdir(wait_analysed_path):
    os.mkdir(os.path.join(CURRENT_PATH, 'ANALYZED_PCAP'))
else:
    pass
analysed_path = os.path.join(CURRENT_PATH, 'ANALYZED_PCAP')
files = os.listdir(wait_analysed_path)

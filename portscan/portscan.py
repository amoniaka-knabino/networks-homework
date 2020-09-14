#!/usr/bin/env python3

import socket
import argparse
import threading
import resource
from itertools import zip_longest
import time

CONNECTION_REFUSED_ERROR_CODE = 111

tcp_ports = []
udp_ports = []
udp_possible_ports = []

tcp_list_lock = threading.Lock()
udp_list_lock = threading.Lock()
udp_possible_list_lock = threading.Lock()

def grouper(iterable, n, fillvalue=None):
    args = [iter(iterable)] * n
    return list(zip_longest(*args, fillvalue=fillvalue))

def get_parsed_args():
    parser = argparse.ArgumentParser(description="scan ports, example: python3 portscan.py scanme.nmap.org -u -p 65 70")
    parser.add_argument("target", help="IP or address")
    parser.add_argument('-t', help='tcp scan',
                        action='store_true',
                        dest='tcp_scan')
    parser.add_argument('-u', help='TODO',
                        action='store_true',
                        dest='udp_scan')
    parser.add_argument("-p", "--ports", nargs="+", dest="ports_range",
                        help="ports_range", type=int)
    parser.add_argument('-o', help='one thread',
                        action='store_true',
                        dest='one_thread')
    return parser.parse_args()


def check_if_port_accept_tcp_conn(ip, port):
	global tcp_ports
	#print(f"tcp scanning {port}", end='\r', flush=True)
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(2)
	result = s.connect_ex((ip, port))
	if(result == 0):
		with tcp_list_lock:
			tcp_ports.append(port)
	s.close()

def scan_multithread(func, ip, n1, n2):
	threads = []
	open_files_os_limit = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
	ports_parts = grouper(range(n1,n2), int(open_files_os_limit/2))
	#print(ports_parts)
	for part in ports_parts:
		for i in part:
			if i is None:
				break
			thread = threading.Thread(target=func, args=(ip, i))
			threads.append(thread)
			thread.start()
		for t in threads:
			if t is None:
				break
			t.join()

def udp_scan_one_port(ip, port):
	#print(f"udp scan {port}")
	global udp_ports
	global possible_udp_ports
	timeout_count = 0
	for _ in range(5):
		with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
			sock.settimeout(8)
			sock.connect((ip, port))
			try:
				sock.send(b'\x00')
				#time.sleep(8)
				data = sock.recvfrom(1024)
				if data:
					with udp_list_lock:
						udp_ports.append(port)
					break
			except socket.timeout:	
				timeout_count+=1
			except socket.error as ex:
				if ex.errno == CONNECTION_REFUSED_ERROR_CODE:
					break
	if timeout_count == 5:
		with udp_possible_list_lock:
			udp_possible_ports.append(port)


def print_result(tcp_ports=[], udp_ports=[], possible_udp=[]):
	for x in tcp_ports:
		print(f"TCP {x}")
	for x in udp_ports:
		print(f"UDP {x}")
	for x in possible_udp:
		print(f"UDP {x} filtered")


if __name__ == '__main__':
	args = get_parsed_args()
	targetIP = socket.gethostbyname(args.target)
	if args.tcp_scan:
		scan_multithread(check_if_port_accept_tcp_conn, targetIP, *args.ports_range)
	if args.udp_scan:
		scan_multithread(udp_scan_one_port, targetIP, *args.ports_range)
	print_result(tcp_ports, udp_ports, udp_possible_ports)


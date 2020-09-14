#!/usr/bin/python3

import socket
import struct
import sys
import subprocess
import io
from contextlib import redirect_stdout
import re
from struct import unpack
from socket import AF_INET, inet_pton

whois_servers = ['whois.arin.net', 'whois.apnic.net',
                 'whois.ripe.net', 'whois.afrinic.net',
                 'whois.lacnic.net']

not_found_messages = ['no entries found', 'no match found', 'no match for']

port = 33434
max_hops = 30


def check_if_private(ip):
    f = unpack('!I', inet_pton(AF_INET, ip))[0]
    private = (
        # 127.0.0.0,   255.0.0.0   http://tools.ietf.org/html/rfc3330
        [2130706432, 4278190080],
        # 192.168.0.0, 255.255.0.0 http://tools.ietf.org/html/rfc1918
        [3232235520, 4294901760],
        # 172.16.0.0,  255.240.0.0 http://tools.ietf.org/html/rfc1918
        [2886729728, 4293918720],
        # 10.0.0.0,    255.0.0.0   http://tools.ietf.org/html/rfc1918
        [167772160,  4278190080],
    )
    for net in private:
        if (f & net[1]) == net[0]:
            return True
    return False


class Node:
    def __init__(self, ip):
        self.ip = ip
        self.AS = -1
        self.country = None
        self.net_name = None

    def load_from_whois(self, response):
        self.net_name = find_any_substring([r"NetName:[\s]*(.*)"], response)
        self.AS = find_any_substring(
            [r"origin:[\s]*(.*)", r"originas:[\s]*(.*)"], response)
        self.country = find_any_substring([r"country:[\s]*(.*)"], response)

    def __str__(self):
        ans = self.ip
        atr = ''
        if self.net_name:
            atr = self.net_name
        if self.AS:
            if atr:
                atr += ', '
            atr += self.AS
        if self.country:
            if atr:
                atr += ', '
            atr += self.country
        return ans + '\r\n' + atr


def check_one_node(dest_name, ttl, dest_addr, icmp, udp):
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp) as recv_socket:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp) as send_socket:
            send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            recv_socket.settimeout(4)
            recv_socket.bind(("0.0.0.0", port))
            print(f"{ttl}. ", end='')
            send_socket.sendto(b"", (dest_name, port))
            curr_addr = None
            finished = False
            tries = 3
            while not finished and tries > 0:
                try:
                    _, curr_addr = recv_socket.recvfrom(512)
                    finished = True
                    curr_addr = curr_addr[0]
                except socket.error:
                    tries = tries - 1
                    if tries == 0:
                        print('*', end='\r\n'*3)
    if not finished:
        pass

    if curr_addr:
        if (check_if_private(curr_addr)):
            print(curr_addr, end='\r\n'*3)
        else:
            print(do_and_parse_whois(curr_addr), end='\r\n'*3)
    if curr_addr == dest_addr or ttl > max_hops:
        return False
    return True


def do_and_parse_whois(addr):
    node = Node(addr)
    server_found = False
    for server in whois_servers:
        ans = _do_whois_query_to_server(addr, server=server)
        for m in not_found_messages:
            if m in ans.lower():
                break
            else:
                server_found = True
    if server_found:
        return parse_whois(ans, node)


def _do_whois_query_to_server(addr, server='whois.iana.org'):
    p = subprocess.Popen(['whois', '-h', server, addr],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    r = p.communicate()[0]
    return r.decode(errors='ignore')


def find_any_substring(reg_list, response):
    for r in reg_list:
        for line in response.split('\n'):
            a = re.findall(r, line, flags=re.IGNORECASE)
            if len(a):
                return a[0]


def parse_whois(response, node):
    node.load_from_whois(response)
    return str(node)


def main(dest_name):
    dest_addr = socket.gethostbyname(dest_name)
    icmp = socket.getprotobyname('icmp')
    udp = socket.getprotobyname('udp')
    ttl = 1
    shouldContinue = True
    while True:
        if (shouldContinue):
            shouldContinue = check_one_node(
                dest_name, ttl, dest_addr, icmp, udp)
            ttl += 1
        else:
            break


if __name__ == "__main__":
    main(sys.argv[1])

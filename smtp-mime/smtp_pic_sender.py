import sys
import re

from socket import socket, AF_INET, SOCK_STREAM, timeout
from ssl import wrap_socket
from argparse import ArgumentParser
from os import getcwd, path, listdir, linesep
from logging import error
from base64 import b64encode
from getpass import getpass


TIMEOUT = 15
ALLOWED_EXTENSIONS = ["jpg", "png", "gif", "bmp", "jpeg"]
SERVER_REPLY_BUFFER = 50

CRLF = "\r\n"
ENCODING = "utf-8"

VERBOSE = False
SERVER_MAX_SIZE = 0  # 0 == inf by RFC1870
SERVER_AUTH = False
SERVER_SSL = False


def get_parsed_args():
    parser = ArgumentParser(
        description="scan ports, example: python3 portscan.py scanme.nmap.org -u -p 65 70")
    parser.add_argument('-ssl', help='let ssl',
                        action='store_true',
                        dest='ssl', default=False)
    parser.add_argument('-s', '--server', help='SMTP-server address[:port]',
                        dest='server', required=True)
    parser.add_argument('-t', '--to', help='reciever address',
                        dest='destination', required=True)
    parser.add_argument('-f', '--from', help='sender address',
                        dest='sender', required=False, default="<>")
    parser.add_argument('--auth', help='require auth',
                        action='store_true',
                        dest='auth', default=False)
    parser.add_argument('-v', '--verbose', help='verbose mode',
                        action='store_true',
                        dest='verbose', default=False)
    parser.add_argument('-d', '--directory', help='image dir',
                        dest='dir', default=getcwd())
    parser.add_argument('--subject', help='mail subject',
                        dest='subject', default="Happy Pictures")
    return parser.parse_args()


def main():
    global VERBOSE
    args = get_parsed_args()
    sender = args.sender
    destination = args.destination
    directory = args.dir
    ssl = args.ssl
    server = args.server.split(':')[0]
    VERBOSE = args.verbose
    if len(args.server.split(':')) > 1:
        port = int(args.server.split(':')[1])  # 25 by default
    else:
        port = 25
    if not path.exists(directory) or not path.isdir(directory):
        print("Incorrect directory.")
        sys.exit(1)
    pictures = [path.basename(picture) for picture in get_pictures(directory)]
    letter = get_letter(pictures, directory, sender, destination, args.subject)
    handle_connection(sender, destination, letter,
                      server, port, ssl, args.auth)

    if SERVER_MAX_SIZE != 0 and len(letter) > SERVER_MAX_SIZE:
        print("Your letter is too large. Please split it to several ones")
        print(f"(max size is {SERVER_MAX_SIZE}, your letter is {len(letter)})")
        sys.exit(1)


def get_pictures(directory):
    for filename in listdir(directory):
        point_idx = filename.find('.')
        if point_idx > 0 and filename[point_idx+1:] in ALLOWED_EXTENSIONS:
            yield filename


def get_main_header(sender, destination, subject):
    header_from = "From: <{}>{}".format(sender, CRLF)
    header_to = "To: <{}>{}".format(destination, CRLF)
    subject = "Subject: {}{}".format(subject, CRLF)
    return header_from + header_to + subject


def get_letter(pictures, directory, sender, destination, subject):
    boundary = "iamaboundary"
    dash_dash_boundary = "--{}".format(boundary)
    header_content = f"Content-Type: multipart/related; charset={ENCODING}; "
    header_boundary = f"boundary={boundary}{CRLF}"
    header = get_main_header(sender, destination, subject) + \
        header_content + header_boundary
    body = ''
    for picture in pictures:
        body += dash_dash_boundary + CRLF
        body += get_attach_header(picture)
        body += read_picture(directory, picture) + CRLF
    body += dash_dash_boundary
    body += "--" + (CRLF * 2) + "."
    return header + CRLF + body


def get_attach_header(picture):
    extension = picture[picture.find('.')+1:]
    body = ''
    body += f"Content-Type: image/{extension}{CRLF}"
    body += f"Content-Transfer-Encoding: base64{CRLF}"
    body += f"Content-ID: <{picture}>{CRLF}"
    body += f'Content-Disposition: attachment; filename="{picture}"{CRLF*2}'
    return body


def read_picture(directory, picture):
    if not directory.endswith(path.sep):
        directory += path.sep
    with open(directory + picture, mode='rb') as letter_file:
        letter = letter_file.read()
        return b64encode(letter).decode(ENCODING)


def handle_connection(source, destination, letter, server, port, ssl, auth):
    sock = socket(AF_INET, SOCK_STREAM)
    sock.settimeout(TIMEOUT)

    try:
        sock.connect((server, port))
        data = sock.recv(512)
        analyse_data(data, "220 ")
        data = send_data(sock, "ehlo test", "250")
        extract_ESMTP(data)
        if ssl:
            send_data(sock, "starttls", "220")
            sock = wrap_socket(sock)
            sock.settimeout(TIMEOUT)
        send_data(sock, "ehlo test", "250")
        if auth:
            send_data(sock, "auth login", "334")
            login = input("Login: ")
            send_data(sock, b64encode(login.encode(
                ENCODING)).decode(ENCODING), "334")
            password = getpass("Password: ")
            send_data(sock, b64encode(password.encode(
                ENCODING)).decode(ENCODING), "235")
        send_letter(sock, source, destination, letter)

    finally:
        sock.close()


def send_data(sock, data, response, verbose=True):
    if VERBOSE and verbose:
        print(f"-> {data}{linesep}")
    sock.send((data + CRLF).encode(ENCODING))
    buff = sock.recv(512)
    analyse_data(buff, response)
    return buff


def extract_ESMTP(data):
    global SERVER_MAX_SIZE, SERVER_AUTH, SERVER_SSL
    for line in data.decode('ascii').split('\n'):
        if "SIZE" in line:
            SERVER_MAX_SIZE = int(line.split(' ')[1])
        if "AUTH" in line:
            SERVER_AUTH = True
        if "STARTTLS" in line:
            SERVER_SSL = True


def analyse_data(data, correct):
    if VERBOSE:
        print(f"<-{data.decode(ENCODING)}")
    data = data.decode(ENCODING)
    if not data.startswith(correct):
        if len(data) > SERVER_REPLY_BUFFER:
            data = data[:SERVER_REPLY_BUFFER] + "..."
        error(f"Unexpected server response:{data}{linesep}")
        sys.exit(1)


def send_letter(sock, source, destination, letter):
    send_data(sock, "mail from: {}".format(source), "250")
    send_data(sock, "rcpt to: {}".format(destination), "250")
    send_data(sock, "data", "354")
    send_data(sock, letter, "250", verbose=False)
    send_data(sock, "quit", "221")


if __name__ == "__main__":
    main()

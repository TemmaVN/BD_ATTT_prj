#!/usr/bin/env python3

import socket
from http.server import HTTPserver, SimpleHTTPRequestHandle

HOST = '0.0.0.0'
PORT = 8080

server = HTTPserver((HOST,PORT),SimpleHTTPRequestHandle)
server.serve_forever()
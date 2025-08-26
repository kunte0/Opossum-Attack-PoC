#!/usr/bin/env python3
from pwn import * 
from scapy.layers.tls.all import TLS


context.log_level = 'info'

LPORT = 1234
RHOST = '127.0.0.1'
RPORT = 631
RPORT_TLS = 631




while True:
    l = listen(LPORT)
    l.wait_for_connection()

    r = remote(RHOST, RPORT)

    upgrade_request = (
        'GET / HTTP/1.1\r\n'
        'Host: 127.0.0.1:631\r\n'
        'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:134.0) Gecko/20100101 Firefox/134.0\r\n'
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n'
        'Accept-Language: en-US,en;q=0.5\r\n'
        'Accept-Encoding: gzip, deflate, br, zstd\r\n'
        'Authorization: Basic cHJpbnQ6cHJpbnQ=\r\n'
        'Cookie: org.cups.sid=DEADC0DE\r\n'
        'Upgrade-Insecure-Requests: 1\r\n'
        'Priority: u=0, i\r\n'
        'Pragma: no-cache\r\n'
        'Cache-Control: no-cache\r\n'
        'Upgrade: TLS/1.0\r\n'
        'Connection: keep-alive\r\n'
        'Connection: upgrade\r\n'
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
                print('Closing sockets')
                src.close()
                dest.close()
                break
            
    t1 = Thread(target=forward, args=(l, r, 'Browser'))
    t2 = Thread(target=forward, args=(r, l, 'Server'))

    t1.start()
    t2.start()


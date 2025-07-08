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
        'POST /admin/ HTTP/1.1\r\n'
        'Host: 127.0.0.1:631\r\n'
        'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0\r\n'
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n'
        'Accept-Language: en-US,en;q=0.5\r\n'
        'Accept-Encoding: gzip, deflate, br, zstd\r\n'
        'Content-Type: application/x-www-form-urlencoded\r\n'
        'Transfer-Encoding: chunked\r\n'
        'Origin: https://127.0.0.1:631\r\n'
        'Authorization: Basic cHJpbnQ6cHJpbnQ=\r\n'
        'Connection: keep-alive\r\n'
        'Referer: https://127.0.0.1:631/admin\r\n'
        'Cookie: org.cups.sid=2abb2da664327c1537dcddc91821cdb7\r\n'
        'Upgrade-Insecure-Requests: 1\r\n'
        'Sec-Fetch-Dest: document\r\n'
        'Sec-Fetch-Mode: navigate\r\n'
        'Sec-Fetch-Site: same-origin\r\n'
        'Sec-Fetch-User: ?1\r\n'
        'Priority: u=0, i\r\n'
        'Pragma: no-cache\r\n'
        'Cache-Control: no-cache\r\n'
        'Upgrade: TLS/1.0\r\n'
        'Connection: Upgrade\r\n'
        '\r\n'
        #'org.cups.sid=2abb2da664327c1537dcddc91821cdb7&OP=config-server'
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
                src.close()
                dest.close()
                print(f'Closed {label}')
                break
            
    t1 = Thread(target=forward, args=(l, r, 'Browser'))
    t2 = Thread(target=forward, args=(r, l, 'Server'))

    t1.start()
    t2.start()


#!/usr/bin/env python3
import socket
import select
import threading
import argparse
import time

def handle_client(client_socket, remote_host, port_opportunistic, port_implicit):
    try:
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.connect((remote_host, port_opportunistic))
        print(f"INFO: Initial connection to {remote_host}:{port_opportunistic} established.")
    except Exception as e:
        print("ERROR: Exception during initial connection", e)
        client_socket.close()
        return

    detected_server_app_data = False
    server_app_data = b""
    switched = False
    sockets = [client_socket, remote_socket]

    try:
        while True:
            r, _, _ = select.select(sockets, [], sockets)
            for s in r:
                data = s.recv(2048)
                if not data:
                    if s is client_socket:
                        print("ERROR: Client closed connection.")
                    else:
                        print("ERROR: Server closed connection.")
                    return
                
                # Daten vom Client
                if s is client_socket:
                    if (not switched) and (len(data) >= 5):
                        content_type = data[0]
                        version_major = data[1]
                        version_minor = data[2]
                        # Prüfe, ob es sich um eine TLS Nachricht handelt
                        if content_type == 22 and version_major == 3 and version_minor in (1, 2, 3, 4):
                            print("INFO: Detected TLS ClientHello message from Client.")
                            print(f"INFO: Switching connection to {remote_host}:{port_implicit}")
                            # Schließe die alte Verbindung und stelle eine neue her
                            remote_socket.close()
                            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            remote_socket.connect((remote_host, port_implicit))
                            sockets[1] = remote_socket 
                            switched = True
                    if switched and detected_server_app_data:
                        print("  C -> S not forwarded")
                        input("ACTION REQUIRED: Press Enter to forward saved AppData...")
                        client_socket.sendall(server_app_data)
                        print("  S -> C forwarded saved AppData")
                        print("INFO: Keep connection open.")
                        print("-------------------------------------------------------------------------")
                        while True:
                            pass
                    # Sende Daten
                    remote_socket.sendall(data)
                    print("  C -> S forwarded")
                # Daten vom Server
                else:
                    # Prüfe, ob es sich um eine CCS, FIN, AppData Nachricht handelt
                    if switched:
                        if b'\x17\x03\x03' in data:
                            print("INFO: Detected CCS, FIN, AppData from Server.")
                            ccs_fin_appdata = data.split(b'\x17\x03\x03')
                            if len(ccs_fin_appdata) == 2:
                                server_app_data = b'\x17\x03\x03' + ccs_fin_appdata[1]
                                detected_server_app_data = True
                                # OpenSSL Fix
                                #client_socket.sendall(ccs_fin_appdata[0])
                                #client_socket.sendall(server_app_data)
                                #break
                            client_socket.sendall(ccs_fin_appdata[0])
                            print("  S -> C forwarded only CCS, FIN")
                        else:
                            client_socket.sendall(data)
                            print("  S -> C forwarded")
                    else:
                        client_socket.sendall(data)
                        print("  S -> C forwarded")
    except Exception as e:
        print("ERROR: Exception during forwarding", e)
    finally:
        client_socket.close()
        remote_socket.close()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lport", type=int, required=True,)
    parser.add_argument("--rhost", type=str, default="127.0.0.1")
    parser.add_argument("--rportO", type=int)
    parser.add_argument("--rportI", type=int)
    parser.add_argument("--protocol", type=str)
    args = parser.parse_args()

    listen_port = args.lport
    remote_host = args.rhost
    port_opportunistic = args.rportO
    port_implicit = args.rportI
    protocol = args.protocol

    if protocol == "imap":
        port_implicit = 993 
        port_opportunistic = 143
    elif protocol == "smtp":
        port_implicit = 465
        port_opportunistic = 587
    elif protocol == "pop3":
        port_implicit = 995
        port_opportunistic = 110
    elif protocol == "lmtp":
        port_implicit = 31024
        port_opportunistic = 31023
    elif protocol == "ftp":
        port_implicit = 21
        port_opportunistic = 2121
    elif protocol == "sieve":
        port_implicit = 4190
        port_opportunistic = 4191 
    else:
        print("ERROR: Unkown protocol. Supported protocols: sieve, imap, smtp, pop3, lmtp, ftp")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", listen_port))
    server.listen(5)
    print("-------------------------------------------------------------------------")
    print(f"Proxy listening on port {listen_port} and initially forwarding to {remote_host}:{port_opportunistic}")
    print("-------------------------------------------------------------------------")

    try:
        while True:
            client_socket, addr = server.accept()
            print(f"INFO: Incoming connection from {addr[0]}:{addr[1]}")
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, remote_host, port_opportunistic, port_implicit),
                daemon=True
            )
            client_thread.start()
    except KeyboardInterrupt:
        print("ERROR: Shutting down proxy.")
    finally:
        server.close()

if __name__ == "__main__":
    main()

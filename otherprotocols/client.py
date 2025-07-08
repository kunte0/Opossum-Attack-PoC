#!/usr/bin/env python3
import argparse
import imaplib
import smtplib
import poplib
from ftplib import FTP_TLS
import managesieve
import ssl

def wrap_message(message):
    border = "-" * len(message)
    return f"{border}\n{message}\n{border}"

def test_imap(host, port, tls_method):
    try:
        if tls_method.lower() == "implicit":
            print(wrap_message("IMAP - Starting encrypted connection."))
            imap = imaplib.IMAP4_SSL(host, port)
            imap.debug = 4
        elif tls_method.lower() == "opportunistic":
            print(wrap_message("IMAP - Starting plaintext connection to upgrade to TLS."))
            imap = imaplib.IMAP4(host, port)
            imap.debug = 4
            imap.starttls()
        print(wrap_message("IMAP - Updatet to TLS."))
        imap.login(user="user", password="password")
        print(wrap_message("IMAP - Keep connection open."))
        while True:
            pass
    except Exception as e:
        print(wrap_message("IMAP - Exception during exection."))
        print(e)

def test_smtp(host, port, tls_method):
    try:
        if tls_method.lower() == "implicit":
            print(wrap_message("SMTP - Starting encrypted connection."))
            smtp = smtplib.SMTP_SSL(host, port)
            smtp.set_debuglevel(1)
        elif tls_method.lower() == "opportunistic":
            print(wrap_message("SMTP - Starting plaintext connection to upgrade to TLS."))
            smtp = smtplib.SMTP(host, port)
            smtp.set_debuglevel(1)
            smtp.starttls()
        print(wrap_message("SMTP - Updatet to TLS."))
        smtp.ehlo()
        print(wrap_message("SMTP - Keep connection open."))
        while True:
            pass
    except Exception as e:
        print(wrap_message("SMTP - Exception during exection."))
        print(e)

def test_pop3(host, port, tls_method):
    try:
        if tls_method.lower() == "implicit":
            print(wrap_message("POP3 - Starting encrypted connection."))
            pop = poplib.POP3_SSL(host, port)
            pop.set_debuglevel(2)
        elif tls_method.lower() == "opportunistic":
            print(wrap_message("POP3 - Starting plaintext connection to upgrade to TLS."))
            pop = poplib.POP3(host, port)
            pop.set_debuglevel(2)
            pop.stls()
        print(wrap_message("POP3 - Updatet to TLS."))
        pop.capa()
        print(wrap_message("POP3 - Keep connection open."))
        while True:
            pass
    except Exception as e:
        print(wrap_message("POP3 - Exception during exection."))
        print(e)

def test_lmtp(host, port, tls_method):
    try:
        if tls_method.lower() == "implicit":
            print("LMTP - No support with implicit TLS.")
            return
        elif tls_method.lower() == "opportunistic":
            print(wrap_message("LMTP - Starting plaintext connection to upgrade to TLS."))
            lmtp = smtplib.LMTP(host, port)
            lmtp.set_debuglevel(1)
            lmtp.starttls()
        print(wrap_message("LMTP - Updatet to TLS."))
        lmtp.ehlo()
        print(wrap_message("LMTP - Keep connection open."))
        while True:
            pass
    except Exception as e:
        print(wrap_message("LMTP - Exception during exection."))
        print(e)

def test_ftp(host, port, tls_method):
    try:
        if tls_method.lower() == "implicit":
            print("FTP - No support with implicit TLS.")
            return
        elif tls_method.lower() == "opportunistic":
            print(wrap_message("FTP - Starting plaintext connection to upgrade to TLS."))
            ftp = FTP_TLS()
            ftp.set_debuglevel(2)
            ftp.connect(host, port)
            ftp.auth()  
        print(wrap_message("FTP - Updatet to TLS."))
        print(f"FTP ({tls_method}) Verbindung zu {host}:{port} erfolgreich.")
        ftp.quit()
        print(wrap_message("FTP - Keep connection open."))
        while True:
            pass
    except Exception as e:
        print(wrap_message("FTP - Exception during exection."))
        print(e)

def test_sieve(host, port, tls_method):
    try:
        if tls_method.lower() == "implicit":
            print("Sieve - No support with implicit TLS.")
            return
        elif tls_method.lower() == "opportunistic":
            print(wrap_message("Sieve - Starting plaintext connection to upgrade to TLS."))
            ssl_context = ssl._create_unverified_context()
            sieve = managesieve.MANAGESIEVE(host, port)
            sieve.starttls(verify=False)
            sieve.capability()
        print(wrap_message("Sieve - Updatet to TLS."))
        print(wrap_message("Sieve - Keep connection open."))
        while True:
            pass
    except Exception as e:
        print(wrap_message("Sieve - Exception during exection."))
        print(e)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--protocol", type=str, required=True)
    parser.add_argument("--tls", type=str, required=True, choices=["implicit", "opportunistic"])
    parser.add_argument("--host", type=str)
    parser.add_argument("--port", type=int)
    args = parser.parse_args()

    protocol = args.protocol.lower()
    tls_method = args.tls.lower()
    host = args.host if args.host else "127.0.0.1"
    
    if protocol == "imap":
        port = args.port if args.port else (993 if tls_method == "implicit" else 143)
        test_imap(host, port, tls_method)
    elif protocol == "smtp":
        port = args.port if args.port else (465 if tls_method == "implicit" else 587)
        test_smtp(host, port, tls_method)
    elif protocol == "pop3":
        port = args.port if args.port else (995 if tls_method == "implicit" else 110)
        test_pop3(host, port, tls_method)
    elif protocol == "lmtp":
        port = args.port if args.port else (31024 if tls_method == "implicit" else 31023)
        test_lmtp(host, port, tls_method)
    elif protocol == "ftp":
        port = args.port if args.port else (21 if tls_method == "implicit" else 2121)
        test_ftp(host, port, tls_method)
    elif protocol == "sieve":
        port = args.port if args.port else (4190 if tls_method == "implicit" else 4191)
        test_sieve(host, port, tls_method)
    else:
        print("Unkown protocol. Supported protocols: sieve, imap, smtp, pop3, lmtp, ftp")

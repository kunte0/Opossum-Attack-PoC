## Servers & Ports

**IMAP-Server:**

- **993** (Implicit TLS)
- **143** (Opportunistic TLS)

**POP3-Server:**

- **995** (Implicit TLS)
- **110** (Opportunistic TLS)

**SMTP-Server:**

- **465** (Implicit TLS)
- **587** (Opportunistic TLS)

**LMTP-Server:**

- **31024** (Implicit TLS)
- **31023** (Opportunistic TLS) -- BROKEN

**FTP-Server:**

- **21** (Implicit TLS)
- **2121** (Opportunistic TLS)

**NNTP-Server:**

- **119** (Implicit TLS) -- BROKEN
- **563** (Opportunistic TLS) -- BROKEN

## Building & Starting

```
docker-compose build --parallel
docker-compose up -d
docker-compose down
```

## Attacker (MITM)
```
python3 attacker.py --lport 1111 --protocol pop3
```

## Client
```
python3 client.py --tls opportunistic --protocol pop3 
```
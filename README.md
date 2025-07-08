
# Opossum Attack PoCs
RFC 2817 - Opossum Attack: Application Layer Desynchronization using Opportunistic TLS

- [Paper](https://opossum-attack.com/opossum.pdf)
- [Website](https://opossum-attack.com/)


## Proof of Concepts
This repository contains proof-of-concepts (PoCs) for the Opossum attack, a desynchronization attack against HTTPS via TLS upgrade headers. 
The PoCs are designed to demonstrate various vulnerabilities and attack vectors that can be exploited using this technique. We provide docker
containers of web servers that implement RFC 2817. 


## Example: Running the CatDog PoC Against Apache2
1. In `servers/apache2/` run `docker compose up --build` -> start apache2
    - port 127.0.0.1:80 is HTTP with HTTP TLS upgrade
    - port 127.0.0.1:443 is HTTPS
1. In `pocs/` run `pipenv install` -> install the required packages scapy and pwntools
1. `pipenv shell` -> start the virtual environment
1. `python attack-catdog.py`-> opens server on https://127.0.0.1:1234 that acts as a proxy
1. `curl -i -k https://127.0.0.1:1234/cat.html` -> response from dog.html is received

## PoCs

Some PoCs use specific files in the Apache webroot. 

- attack-apache-post.py -> Apache request body desynchronization leaks cookie (uses `servers/apache2/www/apache-mitb.html`)
- attack-catdog.py -> Content confusion, request cat.html but the response from dog.html is received
- attack-cups-cookiefixation.py -> Fixate the Anti CSRF token, bypass CSRF protection (uses `servers/apache2/www/cups-csrf.html`)
- attack-cyrus.py -> Cyrus IMAP server Opposum PoC
- attack-icecast.py -> Icecast server Opposum PoC
- attack-purify.py -> Replace DOMPurify with a different script
- attack-rangexss.py -> Use range header to trigger XSS by extracting a particular segment of a response
- attack-selfxss.py -> Example trigger self-XSS with attacker cookie
- attack-session-get.py -> Log the victim into the attacker account via GET
- attack-session-post.py -> Log the victim into the attacker account via POST (not working because of body desynchronization)
- attack-trace.py -> TRACE XSS attack example

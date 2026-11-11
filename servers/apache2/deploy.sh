#!/bin/bash
# Deploy the RFC 2817 Apache demo server to a box with Docker (ports 80 and 443 must be free).
#
#   CERT_DIR=<dir with fullchain.pem and privkey.pem> ./deploy.sh <ssh-host> <domain>
#
# The certificate is obtained on the laptop, so no DNS API token ends up on the server, e.g.:
#   docker run --rm -v "$PWD/le:/etc/letsencrypt" -v "$PWD/cf.ini:/cf.ini:ro" certbot/dns-cloudflare certonly \
#     --dns-cloudflare --dns-cloudflare-credentials /cf.ini -d <domain> \
#     --agree-tos --register-unsafely-without-email --non-interactive
#   (cf.ini: "dns_cloudflare_api_token = ...", chmod 600; then CERT_DIR=le/live/<domain>)
# Run both again to renew. The DNS record must be "DNS only" in Cloudflare, not proxied.
set -euo pipefail
cd "$(dirname "$0")/../.."

HOST=${1:?usage: CERT_DIR=... $0 <ssh-host> <domain>}
DOMAIN=${2:?usage: CERT_DIR=... $0 <ssh-host> <domain>}
CERT_DIR=${CERT_DIR:?set CERT_DIR to the directory with fullchain.pem and privkey.pem}
REMOTE=${REMOTE:-/root/opossum}
SYNC="rsync -a --no-owner --no-group"

ssh "$HOST" "mkdir -p $REMOTE/servers $REMOTE/pocs $REMOTE/certs && chmod 700 $REMOTE/certs"
# comments.txt is runtime data of guestbook.php, never overwrite it
$SYNC --exclude .env --exclude www/comments.txt servers/apache2 "$HOST:$REMOTE/servers/"
# guestbook.php (PHP runs as www-data, uid 33 in the container) must be able to create/delete comments.txt
ssh "$HOST" "chown 33:33 $REMOTE/servers/apache2/www"
$SYNC pocs/opossum.py "$HOST:$REMOTE/pocs/"
# -L: certbot's live/ files are symlinks into archive/
$SYNC -L --chmod=F600 "$CERT_DIR/fullchain.pem" "$CERT_DIR/privkey.pem" "$HOST:$REMOTE/certs/"
ssh "$HOST" "cat > $REMOTE/servers/apache2/.env" <<EOF
DOMAIN=$DOMAIN
CERT_FILE=$REMOTE/certs/fullchain.pem
KEY_FILE=$REMOTE/certs/privkey.pem
EOF
# recreate, so a renewed certificate (new file) is mounted
ssh "$HOST" "cd $REMOTE/servers/apache2 && docker compose up -d --build --force-recreate"
echo "==> https://$DOMAIN/ deployed on $HOST"

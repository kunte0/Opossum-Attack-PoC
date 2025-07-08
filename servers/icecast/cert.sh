#!/bin/bash
# This script generates a self-signed certificate for Icecast HTTPS support.
# It creates a private key, a certificate, then combines them into one PEM file.
# Make sure the "openssl" command is available on your system.

# Configuration
CERT_DIR="/usr/local/share/icecast"
CERT_FILE="icecast.pem"
KEY_FILE="icecast.key"
CRT_FILE="icecast.crt"
VALID_DAYS=3650
# Update these subject details to reflect your organization and domain
SUBJECT="/C=US/ST=State/L=City/O=Organization/OU=Department/CN=localhost"

# Create the certificate directory if it does not exist.
if [ ! -d "$CERT_DIR" ]; then
    echo "Creating certificate directory at $CERT_DIR..."
    mkdir -p "$CERT_DIR" || { echo "Error: Unable to create directory."; exit 1; }
fi

# Generate a 2048-bit RSA private key.
echo "Generating private key..."
openssl genrsa -out "$CERT_DIR/$KEY_FILE" 2048
if [ $? -ne 0 ]; then
    echo "Error generating private key."
    exit 1
fi

# Generate a self-signed certificate with the specified subject and validity period.
echo "Generating self-signed certificate..."
openssl req -new -x509 -key "$CERT_DIR/$KEY_FILE" \
    -out "$CERT_DIR/$CRT_FILE" -days "$VALID_DAYS" \
    -subj "$SUBJECT"
if [ $? -ne 0 ]; then
    echo "Error generating self-signed certificate."
    exit 1
fi

# Combine the private key and certificate into one PEM file.
echo "Combining key and certificate into $CERT_FILE..."
cat "$CERT_DIR/$KEY_FILE" "$CERT_DIR/$CRT_FILE" > "$CERT_DIR/$CERT_FILE"
if [ $? -ne 0 ]; then
    echo "Error combining key and certificate into PEM file."
    exit 1
fi

# Set file permissions: Ensure the Icecast user (icecast) can read the cert file.
echo "Setting ownership and permissions..."
chmod 777 "$CERT_DIR/$CERT_FILE"

# Optionally clean up the separate key and certificate files if no longer needed.
rm "$CERT_DIR/$KEY_FILE" "$CERT_DIR/$CRT_FILE"

echo "Certificate file generated successfully at $CERT_DIR/$CERT_FILE"
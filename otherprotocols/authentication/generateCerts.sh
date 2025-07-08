echo "0/6 - Removing existing files"
rm -f ca.key ca.crt ca.srl server.key server.csr server.crt

echo "1/6 - Generating CA private key"
openssl genrsa -out ca.key 2048 > /dev/null 2>&1

echo "2/6 - Generating self-signed CA certificate"
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt \
  -subj "/C=US/ST=California/L=Los Angeles/O=ExampleCorp Inc./OU=CA Department/CN=ExampleCA/emailAddress=ca@example.org" > /dev/null 2>&1

echo "3/6 - Generating server private key"
openssl genrsa -out server.key 2048 > /dev/null 2>&1

echo "4/6 - Generating CSR for the server"
openssl req -new -key server.key -out server.csr \
  -subj "/C=US/ST=California/L=Los Angeles/O=ExampleCorp Inc./OU=IT Department/CN=server.example.org/emailAddress=admin@example.org" > /dev/null 2>&1

echo "5/6 - Signing the server CSR with the CA"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256 > /dev/null 2>&1

echo "6/6 - Adapting permissions"
chmod 644 server.key
chmod 644 server.crt
openssl genpkey -algorithm RSA -out private_key.pem
openssl req -new -key private_key.pem -out csr.pem -subj "/C=US/ST=New York/L=New York/O=Itest Company/OU=IT/CN=integration.test"
openssl req -x509 -sha256 -days 365 -key private_key.pem -in csr.pem -out certificate.pem
openssl x509 -inform PEM -in certificate.pem -outform DER -out certificate.cer

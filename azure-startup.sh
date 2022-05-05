#!/bin/sh

echo $CERT_FILE_B64 | base64 --decode > cert.pem
echo $KEY_FILE_B64 | base64 --decode > key.pem

python3 -m cadi.main platform-credentials.yml

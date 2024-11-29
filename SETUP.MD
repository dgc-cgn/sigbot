# Setup

Clone this repo. 

Get your private key from your website. If you are using nginx and do a certificate install you will see this for your `<domain name>`

```
Successfully received certificate.
Certificate is saved at: /etc/letsencrypt/live/<domain name>/fullchain.pem
Key is saved at:         /etc/letsencrypt/live/<domain name>/privkey.pem
This certificate expires on 2025-02-26.
These files will be updated when the certificate renews.
Certbot has set up a scheduled task to automatically renew this certificate in the background.
```
You want the ```/etc/letsencrypt/live/<domain name>/privkey.pem```
Create a `ca/root` subdirectory
Copy this file to the `ca/root` directory

Go to the `ca/root` directory. This will need to be your current working directory for the next few steps.


First, check to see if your private key is valid.
```
openssl ec -in privkey.pem -text -noout
```
Create a certificate signing request
```
openssl req -new -key privkey.pem -out request.csr
```

Create a `docsign.cnf' file with the following contents

```
[ req ]
default_bits        = 2048
prompt              = no
default_md          = sha256
distinguished_name  = req_distinguished_name
x509_extensions     = v3_ca

[ req_distinguished_name ]
C                   = CA
ST                  = Ontario
L                   = Ottawa
O                   = Supername
CN                  = supername.app

[ v3_ca ]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, nonRepudiation
extendedKeyUsage = critical, emailProtection, codeSigning
```

Generate the doc signing certificate. Don't worry about the warnings

```
openssl req -x509 -days 365 -key privkey.pem -in request.csr -out docsign.pem -config docsign.cnf -extensions v3_ca -copy_extensions copy
```

Create the passworkd protected `pkcs` file. Don't forget your password!
```
openssl pkcs12 -export -inkey privkey.pem -in docsign.pem -out docsign.p12  -name "Self-Signed Certificate for Document Signing"
```
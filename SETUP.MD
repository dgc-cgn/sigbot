# Setup
```
openssl req -new -key privkey.pem -out request.csr
```
```
openssl req -x509 -days 365 -key privkey.pem -in request.csr -out docsign.pem -config openssl-digsign.cnf -extensions v3_ca
```

```
openssl pkcs12 -export -inkey privkey.pem -in docsign.pem -out docsign.p12  -name "Self-Signed Certificate"
```
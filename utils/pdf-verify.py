#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from endesive import pdf


def main():
    trusted_cert_pems = (
        # demo ca chain
        open("ca/root/docsign.pem", "rb").read(),
        # open("ca/demo2_ca.crt.pem", "rb").read(),
        # demo hsm ca chain
        # open("cert-hsm-ca.pem", "rb").read(),
    )
    print(trusted_cert_pems)
    for fname in (

        "data/doc-signed-cms.pdf",

    ):
        print("*" * 20, fname)
        try:
            data = open(fname, "rb").read()
        except:
            continue
        no = 0

        sig_check = pdf.verify(data, trusted_cert_pems )     
        print(sig_check) 
        if sig_check ==[]:
            print("something is awry!")  
        try:
            for (hashok, signatureok, certok) in pdf.verify(
                data, trusted_cert_pems ):
                print("*" * 10, "signature no:", no)
                print("signature ok?", signatureok)
                print("hash ok?", hashok)
                print("cert ok?", certok)
        except:
            print("errors")

main()

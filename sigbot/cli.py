import click
from utils.helpers import   (get_tls_public_key, 
                             get_tls_certificate,
                             convert_certificate_to_pem,
                            pem_string_to_bytes, 
                            pdf_sign, pdf_verify, 
                            pdf_verify_with_domain, 
                            extract_signatures_and_public_keys
                            
                            )

from utils.getpdfsignatures import(get_pdf_signatures,
                                   raw_ec_public_key_to_pem
                            
                            )

from binascii import hexlify
import logging
logger = logging.getLogger("Utils")
logger.setLevel(logging.DEBUG)  
# Configure the logger's handler and format
if not logger.hasHandlers():
    handler = logging.StreamHandler()  # Output to console
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
         
        
logger.info(f"CLI initialized")
logger.setLevel(logging.INFO)

@click.group()
def cli():
    pass

@click.command(help='display info')
@click.pass_context
def info(ctx):
    
    click.echo("This is sigbot")
    
@click.command(help="Get public key from url")
@click.argument('url')
def pubkey(url):
    pubkey_from_url = get_tls_public_key(url)
    hex_pubkey = hexlify(pem_string_to_bytes(pubkey_from_url.decode()))

    cert_from_url = get_tls_certificate(url)
    cert_pem = convert_certificate_to_pem(cert_from_url)
    try:
        click.echo(f"get pubkey for {url} \n {pubkey_from_url.decode()}")
        click.echo(hex_pubkey)
        click.echo(f"certificate \n {cert_pem}")
    except:
        click.echo(f"Hmmm... Can't seem to get anything from {url}!")

@click.command(help="Sign pdf file")
@click.argument('pdf', default="data/doc.pdf")
@click.option('--p12','-p', default="ca/root/docsign.p12")
def sign(pdf, p12):
    password = click.prompt("Password?")
    click.echo(f"sign {pdf} {password} {p12}")
    msg_out = pdf_sign(pdf,p12,password)

@click.command(help="Verify pdf file")
@click.argument('pdf', default="data/doc-signed.pdf")
@click.option('--pem','-p', default="ca/root/docsign.pem")
@click.option('--domain','-d', default="openproof.org")
def verify(pdf, pem, domain):
   
    click.echo(f"verify {pdf} with {domain}")
    try:
        pdf_verify(pdf,pem,domain)
    except Exception as e:
        click.echo(e)
        return

    # pdf_verify_with_domain(pdf,domain)
    for signature in get_pdf_signatures(pdf):
        certificate = signature.certificate
        raw_key_bytes = certificate.subject_public_key_info.public_key
        pem_key = raw_ec_public_key_to_pem(raw_key_bytes)
        click.echo(f"\nSigning Public Key from Document \n {pem_key}")
        pubkey_from_url = get_tls_public_key(domain).decode()
        click.echo(f"\nSigning Public Key from Website: {domain} \n {pubkey_from_url}")
        hex_pubkey = hexlify(pem_string_to_bytes(pubkey_from_url))
        if pem_key==pubkey_from_url:
            click.echo(f"VERIFIED!!! The signed document is issued from {domain}. This document can be TRUSTED!!! \n")
        else:
            click.echo(f"WARNING!!! The signed document is NOT issued from {domain}! While this document has not been altered since being signed, this document SHOULD NOT BE NECESSARILY TRUSTED as being issued by {domain}!!!\n")

@click.command(help="Extract signatures")
@click.argument('pdf', default="data/doc-signed.pdf")

def extract(pdf):
   
    click.echo(f"extract signatures from {pdf}")
    out = extract_signatures_and_public_keys(pdf)
    
    

cli.add_command(info)
cli.add_command(pubkey)
cli.add_command(sign)
cli.add_command(verify)
cli.add_command(extract)

if __name__ == "__main__":
   cli()
import click
from utils.helpers import   (get_tls_public_key, 
                             get_tls_certificate,
                             convert_certificate_to_pem,
                            pem_string_to_bytes, 
                            pdf_sign, pdf_verify, 
                            pdf_verify_with_domain, 
                            extract_signatures_and_public_keys,
                            is_valid_domain,
                            read_trust_list,
                            is_authorized
                            
                            )

from utils.getpdfsignatures import(get_pdf_signatures,
                                   raw_ec_public_key_to_pem,
                                   parse_certificate,
                                   get_pem_public_key_from_certificate
                            
                            )

from binascii import hexlify
import logging, asyncio
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
@click.option('--domain','-d', default='verify.openproof.org')
def verify(pdf, pem, domain):
   
    click.echo(f"verify {pdf} with {domain}")
    try:
        all_sigok, all_hashok = pdf_verify(pdf,pem)
    except Exception as e:
        click.echo(e)
        return

    if all_sigok and all_hashok:
        click.echo("All signatures and hashes validate as OK!")

        try:
            for signature in get_pdf_signatures(pdf):
                certificate = signature.certificate
                # parse_certificate(certificate=certificate)
                certificate_common_name = certificate.issuer.common_name
                click.echo(f"certificate issuer common name: {certificate_common_name}")
                
                public_key_pem = get_pem_public_key_from_certificate(certificate)
                click.echo(f"pem data: {public_key_pem}")

                click.echo(f"\nSigning Public Key from Document: \n\n {public_key_pem}")
                if is_valid_domain(certificate_common_name):
                    domain = certificate_common_name
                    pubkey_from_url = get_tls_public_key(domain).decode()
                    click.echo(f"\nSigning Public Key from Website: {domain} \n\n {pubkey_from_url}")
                    hex_pubkey = hexlify(pem_string_to_bytes(pubkey_from_url))
                    if public_key_pem==pubkey_from_url:
                        click.echo(f"VERIFIED!!! This document is signed by {domain}. \nThis document CAN BE TRUSTED as being verified by: {domain}!!! \n")
                    else:
                        click.echo(f"ADVISORY!!! The signed document is NOT verified by {domain}! \nWhile this document has been digitally signed and not altered, this document SHOULD NOT BE TRUSTED as being verified by {domain}!!!\n")
        except Exception as e:
            click.echo(f"{e}")
    else:
        msg_out ="\nWARNING!!! This document is not signed or has been altered since signing.\nTHIS DOCUMENT MAY BE FRAUDULENT. DO NOT TRUST!!!\n"     
        click.echo(msg_out)

@click.command(help="Extract signatures")
@click.argument('pdf', default="data/doc-signed.pdf")

def extract(pdf):
   
    click.echo(f"extract signatures from {pdf}")
    out = extract_signatures_and_public_keys(pdf)
    

@click.command("authorized", help="Trust pdf file")
@click.argument('trust_list_file', default="trustlists/authorized.jsonl")
@click.option('--domain','-d', default="trustroot.ca")
@click.option('--grant','-g', default="issuer")

def authorized(trust_list_file, domain, grant): 
    auth_check = asyncio.run(is_authorized(trust_list_file,domain, grant))
    fg = "green" if auth_check else "red"
    click.echo(click.style(f"{domain} authorized via {trust_list_file} trustlist for {grant}: {auth_check}",fg=fg, bold=True))   

cli.add_command(info)
cli.add_command(pubkey)
cli.add_command(sign)
cli.add_command(verify)
cli.add_command(extract)
cli.add_command(authorized)

if __name__ == "__main__":
   cli()
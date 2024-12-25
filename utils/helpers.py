import ssl, sys, io, re, os
import socket, jsonlines
import httpx, qrcode, reportlab
from reportlab.pdfgen import canvas
from io import BytesIO
from urllib.parse import urlparse
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12, load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes 
# from endesive.pdf import cms
from endesive import pdf
from PyPDF2 import PdfReader, PdfWriter, PdfFileMerger
from PIL import Image
from cryptography.x509.oid import NameOID
from cryptography.x509 import CertificateBuilder
from cryptography.hazmat.backends import default_backend

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4

from cryptography.hazmat.primitives import serialization
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
         
        
logger.info(f"Function initialized")

UPLOAD_DIR = "uploads"

def is_valid_domain(domain):
    """
    Validate if a string is a valid domain name.

    Args:
        domain (str): The domain name to validate.

    Returns:
        bool: True if the domain is valid, False otherwise.
    """
    # Regular expression to match a valid domain name
    domain_regex = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\."  # Subdomain
        r"(?!-)(?:[A-Za-z0-9-]{1,63}\.)?"   # Optional second-level domain
        r"(?!-)[A-Za-z]{2,63}$"             # Top-level domain
    )

    return bool(domain_regex.match(domain))

def fix_url(url):
    """This is to fix github urls"""
    url = url.replace("https://github.com","https://raw.githubusercontent.com").replace("/blob","")

    return url

def get_tls_public_key(url, port=443):
    # Create an SSL context

    try:
        context = ssl.create_default_context()

        # Connect to the server and get the certificate
        with socket.create_connection((url, port)) as sock:
            with context.wrap_socket(sock, server_hostname=url) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)

        # Load the certificate using cryptography
        certificate = load_der_x509_certificate(der_cert)
        
        # Extract the public key
        public_key = certificate.public_key()
        
        # Convert the public key to PEM format
        public_key_pem = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )
    except:
        return None

    return public_key_pem

def get_tls_certificate(domain, port=443):
    """
    Retrieves the TLS certificate from the given domain.

    Args:
        domain (str): The domain name to connect to.
        port (int): The port to connect to (default is 443 for HTTPS).

    Returns:
        x509.Certificate: The X.509 certificate object.
    """
    # Create an SSL context
    context = ssl.create_default_context()

    # Establish a connection to the server
    with socket.create_connection((domain, port)) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            der_cert = ssock.getpeercert(binary_form=True)

    # Convert the DER certificate to an X.509 certificate object
    certificate = x509.load_der_x509_certificate(der_cert, default_backend())

    return certificate

def convert_certificate_to_pem(certificate):
    """
    Converts an X.509 certificate to PEM format.

    Args:
        certificate (x509.Certificate): An X.509 certificate object.

    Returns:
        str: The certificate in PEM format as a string.
    """
    pem_certificate = certificate.public_bytes(encoding=Encoding.PEM)
    return pem_certificate.decode("utf-8")

def pem_string_to_bytes(pem_string, output_format="DER"):
    """
    Converts a public key from a PEM string to bytes.

    Args:
        pem_string (str): The public key in PEM format as a string.
        output_format (str): Desired output format: "DER" or "PEM".
                             Default is "DER".
                             
    Returns:
        bytes: The public key in the requested format as bytes.
    """
    # Load the public key from the PEM string
    public_key = serialization.load_pem_public_key(pem_string.encode())

    # Choose the encoding format
    if output_format.upper() == "DER":
        encoding = serialization.Encoding.DER
    elif output_format.upper() == "PEM":
        encoding = serialization.Encoding.PEM
    else:
        raise ValueError("Invalid output format. Choose 'DER' or 'PEM'.")

    # Convert the public key to bytes
    public_key_bytes = public_key.public_bytes(
        encoding=encoding,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return public_key_bytes

def pdf_sign(doc_to_sign, p12_to_use, domain, password):
    # domain = "trustroot.ca"
    pdf_add_page = doc_to_sign.replace(".pdf","-addpage.pdf")
    page_index, add_page_file = add_blank_page(doc_to_sign,pdf_add_page)
    print(f"no of pages: {page_index} {add_page_file}")
        # Do the image stuff
    
    #Generate verification QRCode
    
    
    # Convert the image to a PDF page
    image_path = "data/qrimage.png"
    image_pdf_path = "data/sigpage.pdf"
    image_size = None
    position = (0,0)

    verification_url = f"https://{domain}"
    generate_qr_code(verification_url,image_path)

    # Create a canvas
    c = canvas.Canvas(image_pdf_path,pagesize=A4)
    width, height = c._pagesize
    print(width, height)
    # Add text
    c.drawString(20, 750, "This is the signature page for a verifiable pdf")
    # Add an image
    c.drawImage(image_path, 150, 450, 256,256)
    # Save the PDF
    c.save()

    # Open the image PDF
    image_reader = PdfReader(image_pdf_path)
    image_page = image_reader.pages[0]
    print(f"image page size: {image_page.mediabox.width} {image_page.mediabox.height} ")


    reader = PdfReader(add_page_file)
    writer = PdfWriter()
    target_page = reader.pages[page_index]
    print(f"target page size: {target_page.mediabox.width} {target_page.mediabox.height} ")
    
    # Specify the position of the image on the target page
    
    x_left = (target_page.mediabox.width - image_page.mediabox.width) / 2
    y_bottom = (target_page.mediabox.height - image_page.mediabox.height) / 2

    print(f"x_left {x_left} y_bottom {y_bottom}")
    position_lower_left = (0,0)
    position_upper_right = (position[0]+ image_page.mediabox.width,position[1]+image_page.mediabox.height)
    image_page.mediabox.lower_left = position_lower_left
    image_page.mediabox.upper_right = position_upper_right
    
    
    target_page.merge_page(image_page)
        # Add all pages back into the writer
    for page in reader.pages:
        writer.add_page(page)

        # Save the output PDF
    with open(add_page_file, "wb") as f:
        writer.write(f)
    
    date = datetime.utcnow()
    date = date.strftime("D:%Y%m%d%H%M%S+00'00'")
    dct = {
        "aligned": 8192,
        "sigflags": 3,
        "sigflagsft": 132,
        "sigpage": page_index,
        "sigbutton": True,
        "sigfield": "Signature1",
        "auto_sigfield": True,
        "sigandcertify": True,
        "signaturebox": (100, 200, 400, 650),
        "signature": f"This PDF has been digitally signed by {domain} on {date}. Verify with QR Code below.",
        "signature_img": "data/qrimg.png",
        "contact": "info@trustroot.ca",
        "location": "Canada",
        "signingdate": date,
        "reason": "Verifiable PDF",
        "password": "1234",
    }
    with open(p12_to_use, "rb") as fp:
        p12 = pkcs12.load_key_and_certificates(
            fp.read(), password.encode(), backends.default_backend()
        )
    fname = add_page_file
    print(f"fname: {fname}")

    datau = open(fname, "rb").read()
    datas = pdf.cms.sign(datau, dct, p12[0], p12[1], p12[2], "sha256")
    fname_signed = fname.replace(".pdf", "-signed.pdf").replace("-addpage","")
    with open(fname_signed, "wb") as fp:
        fp.write(datau)
        fp.write(datas)

    os.remove(fname)
    # os.remove(image_pdf_path)
    # os.remove(image_path)

def pdf_verify_with_domain(pdf_to_verify, domain):


    public_key_pem = get_tls_public_key(domain).decode()
    logger.debug(f"domain: {domain} {public_key_pem}")

    result = pdf_verify_with_public_key(pdf_to_verify,public_key_pem)
    logger.debug(result)
    return result
    


def pdf_verify(pdf_to_verify, pem_to_use):
    all_hashok = True
    all_sigok = True
    msg_out = f"Issuer to verify"
    # print(f"Domain to verify: {domain}")
    # tls_pubkey = get_tls_public_key(domain)
    # tls_cert = get_tls_certificate(domain)
   
    # 
    # pem_certificate = tls_cert.public_bytes(encoding=Encoding.PEM).decode("utf-8")
    # print(f"TLS Public Key and Cert: {tls_pubkey} {tls_cert} {pem_to_use} {pem_certificate}")
   
    
    # create_self_signed_certificate_from_public_key(tls_pubkey_pem)
    
   

    trusted_cert_pems = (
        
        open(pem_to_use, "rb").read(),

       
    )
    
    for fname in (

        pdf_to_verify,

    ):
        print(f"Document to verify: {fname}")
        try:
            data = open(fname, "rb").read()
        except:
            continue
        no = 0

        sig_check = pdf.verify(data, trusted_cert_pems )     
        # print(sig_check) 
        if sig_check ==[]:
            
            return False, False 
        try:
            for (hashok, signatureok, certok) in pdf.verify(
                data, trusted_cert_pems ):
                print("*" * 10, "signature no:", no)
                print("signature ok?", signatureok)
                print("hash ok?", hashok)
                all_hashok = all_hashok and hashok
                all_sigok = all_sigok and signatureok
                if not certok:
                    msg_out = "\nADVISORY!!! The certificate used to sign this document is not in a trust registry known by this site. However, this document CAN BE TRUSTED if the public key used to sign this document is the SAME as what originates from the issuing website. Checking this now..."
                else:    
                    print("Signing certificate is trusted by this site.", certok)
                    msg_out = "Document signing certificate is trusted by this site."
        except:
            print("errors")

    return all_sigok, all_hashok

def create_temporary_certificate(public_key_pem):
    """
    Creates a proper self-signed X.509 certificate using a random private key.

    Args:
        public_key_pem (str): The public key in PEM format.

    Returns:
        bytes: The DER-encoded certificate.
    """
    # Load the public key from PEM
    public_key = load_pem_public_key(public_key_pem.encode())
    print(f"public key: {hexlify(public_key.public_bytes(format=PublicFormat.SubjectPublicKeyInfo, encoding=Encoding.DER)).decode()}")

    
    # Generate a random private key for signing the certificate
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Define subject and issuer (self-signed, so they're the same)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CA"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Ontario"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Ottawa"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Organization"),
        x509.NameAttribute(NameOID.COMMON_NAME, "openbalance.app"),
    ])

    # Create the self-signed certificate
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)  # Use the provided public key
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))  # Valid for 1 year
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .sign(private_key, hashes.SHA256())  # Sign with the randomly generated private key
    )
    with open("ca/root/certificate.pem", "wb") as cert_file:
        cert_file.write(certificate.public_bytes(Encoding.PEM))

    # Return the PEM-encoded certificate
    return certificate.public_bytes(encoding=Encoding.PEM)

def pdf_verify_with_public_key(pdf_path, public_key_pem):
    """
    Verifies a digitally signed PDF using only a public key.

    Args:
        pdf_path (str): Path to the signed PDF file.
        public_key_pem (str): The public key in PEM format.

    Returns:
        dict: Verification details.
    """
    # Create a temporary certificate from the public key
    temporary_certificate = create_temporary_certificate(public_key_pem)

    logger.debug(f"temporary certificate: \n\n {temporary_certificate.decode()}")

    # Read the signed PDF
    with open(pdf_path, "rb") as pdf_file:
        pdf_data = pdf_file.read()

    # Verify the PDF using the temporary certificate
    verification_result = pdf.verify(pdf_data, [temporary_certificate])

    return verification_result

def extract_signatures_and_public_keys(pdf_path):
    """
    Extract public keys from the signatures in a PDF file.

    Args:
        pdf_path (str): Path to the signed PDF.

    Returns:
        list: A list of public keys in PEM format.
    """
    public_keys = []

    # Read the PDF file
    with open(pdf_path, "rb") as pdf_file:
        pdf_data = pdf_file.read()

    # Verify the PDF signatures
    signature_verification_results = pdf.verify(pdf_data)

    if not signature_verification_results:
        print("No signatures found or verification failed.")
        return public_keys

    print(f"Number of signatures found: {len(signature_verification_results)}")

    for idx, signature_data in enumerate(signature_verification_results):
        print(f"Processing signature {idx + 1}...")

        # signature_data is a tuple; the second element contains signature details
        signature_info = signature_data[1] if isinstance(signature_data, tuple) else None

        if not signature_info:
            print(f" - No signature details found for signature {idx + 1}")
            continue

        # Extract the signing certificate in DER format
        der_cert = signature_info.get("signing_cert", None)
        if not der_cert:
            print(f" - No certificate found for signature {idx + 1}")
            continue

        # Load the DER certificate using cryptography
        certificate = load_der_x509_certificate(der_cert)

        # Extract the public key from the certificate
        public_key = certificate.public_key()

        # Serialize the public key to PEM format
        public_key_pem = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )

        # Print and store the public key
        print(f" - Public Key (PEM format):\n{public_key_pem.decode()}")
        public_keys.append(public_key_pem.decode())

    return public_keys

def trust_pdf(pdf: str):
    """This is the function that does the full trust evalution
    1. Is the hash valid?
    2. Is the signature valid?
    3. Is the public key trusted?
    4. (Optional) Is the public key authorized?
    """

def read_trust_list(trust_list_file):
    with jsonlines.open(trust_list_file) as reader:
        for record in reader:
            print(record)
    return reader

async def is_authorized(trust_list_file, domain, grant):
    authorized = False

    try:
        parsed_url = urlparse(trust_list_file)
        if not parsed_url.scheme or not parsed_url.netloc:
            print("this is a file")


        else:
            print("this is a url")
            trust_list_url = fix_url(trust_list_file)
            
            try:
                # Download the PDF
                async with httpx.AsyncClient() as client:
                    response = await client.get(trust_list_url)
                    response.raise_for_status()

                # Check if the content type indicates a PDF
                content_type = response.headers.get("Content-Type", "").lower()


                # Save the PDF to the local directory
                filename = os.path.join(UPLOAD_DIR, os.path.basename(trust_list_file))
                with open(filename, "wb") as f:
                    f.write(response.content)
            except httpx.HTTPError as e:
                raise ValueError(status_code=400, detail=f"Failed to download PDF: {str(e)}")
            except Exception as e:
                raise ValueError(status_code=500, detail=f"An unexpected error occurred: {str(e)}")
            

            trust_list_file = filename
            
    except Exception as e:
        pass
        return False
    
    print(trust_list_file)
    with jsonlines.open(trust_list_file) as reader:
        for each in reader:
            if each['domain'] == domain:
                for each_grant in each['grants']:
                    if each_grant == grant:
                        authorized = True
                        break
    

    return authorized

def add_blank_page(input_pdf_path, output_pdf_path, width=None, height=None):
    """
    Reads a PDF, appends a blank page (with optional width/height),
    and writes out the new PDF to `output_pdf_path`.
    """
    # Load existing PDF
    reader = PdfReader(input_pdf_path)
    writer = PdfWriter()



    # Copy all pages from the original PDF
    for page in reader.pages:
        writer.add_page(page)

    # If width/height not specified, use size from the first page
    if width is None or height is None:
        first_page = reader.pages[0]
        width = first_page.mediabox.width
        height = first_page.mediabox.height

    # Add a blank page
    new_page = writer.add_blank_page(width=width, height=height)

    # Write out the new PDF with the extra blank page
    with open(output_pdf_path, "wb") as f:
        writer.write(f)

    


    return len(reader.pages),output_pdf_path  # old page count (the new page index is old_page_count)

def generate_qr_code(data, file_path):
    """
    Generate a QR code from the given string and save it as a PNG file.

    :param data: The string data to encode in the QR code.
    :param file_path: The file path to save the QR code image (e.g., 'qrcode.png').
    """
    # Create a QR Code object
    qr = qrcode.QRCode(
        version=1,  # controls the size of the QR code (1 is smallest)
        error_correction=qrcode.constants.ERROR_CORRECT_L,  # error correction level
        box_size=10,  # size of each box in the QR code grid
        border=4,  # thickness of the border (minimum is 4)
    )
    qr.add_data(data)
    qr.make(fit=True)

    # Create the image
    img = qr.make_image(fill_color="black", back_color="white")

    # Save the image to the specified file path
    img.save(file_path)
    print(f"QR code saved to {file_path}")


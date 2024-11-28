import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate
import endesive.pdf

certificate_file ='ca/certificate.pem'
private_key_file ='ca/private_key.pem'
input_pdf ='data/pdf.pdf'

with open(private_key_file, "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None  # Add password if your private key is encrypted
        )

with open(certificate_file, "rb") as cert_file:
    certificate = load_pem_x509_certificate(cert_file.read())

print(certificate.public_bytes)
print("private key", private_key)

certificate_der = certificate.public_bytes(serialization.Encoding.DER)

dct = {
        'sigpage': 0,  # Page number to apply the signature (0-indexed)
        'sigbutton': True,  # Create a visible signature button
        'sigfield': 'Signature1',  # Name of the signature field
        'signaturebox': (100, 100, 400, 200),  # Signature box coordinates (x1, y1, x2, y2)
        'signingdate': datetime.datetime.utcnow(),  # UTC signing date
        'reason': 'Document approval',  # Reason for signing
        'location': 'New York, USA',  # Location of signing
        'contact': 'contact@example.com',  # Contact information
    }

    # Read the input PDF
with open(input_pdf, "rb") as pdf_file:
    pdf_data = pdf_file.read()

print(pdf_data)

# Sign the PDF using the private key and certificate
signed_pdf = endesive.pdf.cms.sign(
        pdf_data,
        dct,
        private_key,
        certificate,
        None
        
    )


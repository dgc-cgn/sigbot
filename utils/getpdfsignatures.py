#!/usr/bin/env python
import datetime
import sys

from asn1crypto import cms
from dateutil.parser import parse
from pypdf import PdfReader

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, SECP256R1
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from utils.helpers import convert_certificate_to_pem

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

class AttrClass:
    """Abstract helper class"""

    def __init__(self, data, cls_name=None):
        self._data = data
        self._cls_name = cls_name

    def __getattr__(self, name):
        try:
            value = self._data[name]
        except KeyError:
            value = None
        else:
            if isinstance(value, dict):
                return AttrClass(value, cls_name=name.capitalize() or self._cls_name)
        return value

    def __values_for_str__(self):
        """Values to show for "str" and "repr" methods"""
        return [
            (k, v) for k, v in self._data.items()
            if isinstance(v, (str, int, datetime.datetime))
        ]

    def __str__(self):
        """String representation of object"""
        values = ", ".join([
            f"{k}={v}" for k, v in self.__values_for_str__()
        ])
        return f"{self._cls_name or self.__class__.__name__}({values})"

    def __repr__(self):
        return f"<{self}>"


class Signature(AttrClass):
    """Signature helper class

    Attributes:
        type (str): 'timestamp' or 'signature'
        signing_time (datetime, datetime): when user has signed
            (user HW's clock)
        signer_name (str): the signer's common name
        signer_contact_info (str, None): the signer's email / contact info
        signer_location (str, None): the signer's location
        signature_type (str): ETSI.cades.detached, adbe.pkcs7.detached, ...
        certificate (Certificate): the signers certificate
        digest_algorithm (str): the digest algorithm used
        message_digest (bytes): the digest
        signature_algorithm (str): the signature algorithm used
        signature_bytes (bytest): the raw signature
    """

    @property
    def signer_name(self):
        return (
            self._data.get('signer_name') or
            getattr(self.certificate.subject, 'common_name', '')
        )


class Subject(AttrClass):
    """Certificate subject helper class

    Attributes:
        common_name (str): the subject's common name
        given_name (str): the subject's first name
        surname (str): the subject's surname
        serial_number (str): subject's identifier (may not exist)
        country (str): subject's country
    """
    pass


class Certificate(AttrClass):
    """Signer's certificate helper class

    Attributes:
        version (str): v3 (= X509v3)
        serial_number (int): the certificate's serial number
        subject (object): signer's subject details
        issuer (object): certificate issuer's details
        signature (object): certificate signature
        extensions (list[OrderedDict]): certificate extensions
        validity (object): validity (not_before, not_after)
        subject_public_key_info (object): public key info
        issuer_unique_id (object, None): issuer unique id
        subject_uniqiue_id (object, None): subject unique id
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.subject = Subject(self._data['subject'])

    def __values_for_str__(self):
        return (
            super().__values_for_str__() +
            [('common_name', self.subject.common_name)]
        )


def parse_pkcs7_signatures(signature_data: bytes):
    """Parse a PKCS7 / CMS / CADES signature"""
    content_info = cms.ContentInfo.load(signature_data).native
    if content_info['content_type'] != 'signed_data':
        return None
    content = content_info['content']
    certificates = content['certificates']
    # each PKCS7 / CMS / CADES could have several signatures
    signer_infos = content['signer_infos']
    for signer_info in signer_infos:
        # the sid key should point to the certificates collection
        sid = signer_info['sid']
        digest_algorithm = signer_info['digest_algorithm']['algorithm']
        signature_algorithm = signer_info['signature_algorithm']['algorithm']
        signature_bytes = signer_info['signature']
        # signed attributes is a list of key, value pairs
        # oversimplification: normally we have no repeated attributes
        signed_attrs = {
            sa['type']: sa['values'][0] for sa in signer_info['signed_attrs']}
        # find matching certificate, only for issuer / serial number
        for cert in certificates:
            cert = cert['tbs_certificate']
            if (
                sid['serial_number'] == cert['serial_number'] and
                sid['issuer'] == cert['issuer']
            ):
                break
        else:
            raise RuntimeError(
                f"Couldn't find certificate in certificates collection: {sid}")
        yield dict(
            sid=sid,
            certificate=Certificate(cert),
            digest_algorithm=digest_algorithm,
            signature_algorithm=signature_algorithm,
            signature_bytes=signature_bytes,
            signer_info=signer_info,
            **signed_attrs,
        )


def get_pdf_signatures(filename):
    """Parse PDF signatures"""
    reader = PdfReader(filename)
    try:
        fields = reader.get_fields().values()
    except:
        raise Exception("Could not find signatures")
        return
    
    signature_field_values = [
        f.value for f in fields if f.field_type == '/Sig']
    for v in signature_field_values:
        # - signature datetime (not included in pkcs7) in format:
        #   D:YYYYMMDDHHmmss[offset]
        #   where offset is +/-HH'mm' difference to UTC.
        v_type = v['/Type']
        if v_type in ('/Sig', '/DocTimeStamp'):  # unknow types are skipped
            is_timestamp = v_type == '/DocTimeStamp'
            try:
                signing_time = parse(v['/M'][2:].strip("'").replace("'", ":"))
            except KeyError:
                signing_time = None
            # - used standard for signature encoding, in my case:
            # - get PKCS7/CMS/CADES signature package encoded in ASN.1 / DER format
            raw_signature_data = v['/Contents']
            # if is_timestamp:
            for attrdict in parse_pkcs7_signatures(raw_signature_data):
                if attrdict:
                    attrdict.update(dict(
                        type='timestamp' if is_timestamp else 'signature',
                        signer_name=v.get('/Name'),
                        signer_contact_info=v.get('/ContactInfo'),
                        signer_location=v.get('/Location'),
                        signing_time=signing_time or attrdict.get('signing_time'),
                        signature_type=v['/SubFilter'][1:],  # ETSI.CAdES.detached, ...
                        signature_handler=v['/Filter'][1:],
                        raw=raw_signature_data,
                    ))
                    yield Signature(attrdict)



def raw_ec_public_key_to_pem(raw_key_bytes):
    """
    Converts a raw EC public key into PEM format.

    Args:
        raw_key_bytes (bytes): The raw public key bytes.

    Returns:
        str: The public key in PEM format.
    """
    # Define the elliptic curve (SECP256R1 is commonly used)
    curve = SECP256R1()

    # Create an EllipticCurvePublicKey object from the raw key bytes
    public_key = EllipticCurvePublicKey.from_encoded_point(curve, raw_key_bytes)

    # Serialize the public key to PEM format
    pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )

    return pem.decode("utf-8")

def parse_certificate(certificate):
    
    print(certificate)
    print(certificate.version)
    print(certificate.serial_number)
    print(certificate.common_name)
    print(f"Signer's certificate: {certificate}")
    print(f"  - not before: {certificate.validity.not_before}")
    print(f"  - not after: {certificate.validity.not_after}")
    print(f"  - issuer: {certificate.issuer}")
    print(f"  - issuer country: {certificate.issuer.country_name}")
    print(f"  - issuer organization name: {certificate.issuer.organization_name}")
    print(f"  - issuer organization unit: {certificate.issuer.organizational_unit_name}")
    print(f"  - issuer common_name: {certificate.issuer.common_name}")
    subject = certificate.subject
    print(f"  - subject: {subject}")
    print(f"    - subject common name: {subject.common_name}")
    print(f"    - subject organization identifier: {subject.organization_identifier}")
    print(f"    - serial number: {subject.serial_number}")
    
    
    return

def get_pem_public_key_from_certificate(certificate):
    pubkey_data = certificate.subject_public_key_info.public_key
        
    if isinstance(pubkey_data, bytes):
        public_key_pem = raw_ec_public_key_to_pem(pubkey_data)
        
    else:
        pem_data ="not supported"
        # print(f"modulus: {pubkey_data.modulus}, \nexponent: {pubkey_data.public_exponent}")
        public_key = rsa.RSAPublicNumbers(pubkey_data.public_exponent, pubkey_data.modulus).public_key()
        public_key_pem = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
            ).decode()
    return public_key_pem

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <filename>")
        sys.exit(1)
    filename = sys.argv[1]
    for signature in get_pdf_signatures(filename):
        print(f"--- {signature.type} ---")
        print(f"Signature: {signature}")
        print(f"Signer: {signature.signer_name}")
        print(f"Signing time: {signature.signing_time}")
        certificate = signature.certificate
        print(f"Signer's certificate: {certificate}")
        print(f"  - not before: {certificate.validity.not_before}")
        print(f"  - not after: {certificate.validity.not_after}")
        print(f"  - issuer: {certificate.issuer}")
        subject = signature.certificate.subject
        print(f"  - subject: {subject}")
        print(f"    - common name: {subject.common_name}")
        print(f"    - serial number: {subject.serial_number}")
        
        raw_key_bytes = certificate.subject_public_key_info.public_key
        pem_key = raw_ec_public_key_to_pem(raw_key_bytes)
        print(pem_key)
        
        

        

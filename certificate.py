# Copyright is waived. No warranty is provided. Unrestricted use and modification is permitted.

import sys
import json
import datetime

# Import non-standard modules
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError:
    sys.exit("Cryptography module not found; try 'pip install cryptography'")

PURPOSE = """\
Create a self-signed certificate

certificate.py [bits=<n>] [days=<n>] info=<path> cert=<path>

where,
   bits   optional, number of bits for certificate private key (default = 2048)
   days   optional, number of days from present that certificate is valid for (default = 365)
   info   input path to JSON file with certificate information in X.509 naming scheme
   cert   output path to certificate file
"""


def create_self_signed_certificate(bits, days, information):

    # Generate a keypair for the certificate
    private_key = rsa.generate_private_key(65537, bits, default_backend())

    # Generate validity period for certificate
    start_time = datetime.datetime.utcnow()
    end_time = start_time + datetime.timedelta(days)

    # Generate a certificate signing request
    builder = x509.CertificateBuilder()
    builder = builder.public_key(private_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, information["C"]),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, information["ST"]),
        x509.NameAttribute(NameOID.LOCALITY_NAME, information["L"]),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, information["O"]),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, information["OU"]),
        x509.NameAttribute(NameOID.COMMON_NAME, information["CN"]),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, information["EMAIL"])
    ])
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(subject)
    builder = builder.not_valid_before(start_time)
    builder = builder.not_valid_after(end_time)
    san = x509.SubjectAlternativeName([
        x509.DNSName(information["CN"])
    ])
    builder = builder.add_extension(san, critical=False)

    # Generate self-signed certificate
    certificate = builder.sign(private_key, hashes.SHA256(), default_backend())
    certificate_bytes = certificate.public_bytes(serialization.Encoding.PEM).strip()
    private_key_bytes = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=NoEncryption())
    return private_key_bytes.decode("latin_1"), certificate_bytes.decode("latin_1")


if __name__ == '__main__':

    if sys.version_info < (3, 6):
        sys.exit("Python version must be 3.6 or later")
    if len(sys.argv) < 3:
        sys.exit(PURPOSE)

    num_bits = next((x.split("=", 1)[-1] for x in sys.argv if x.find("bits=") == 0), None)
    num_bits = int(num_bits) if num_bits else 2048
    num_days = next((x.split("=", 1)[-1] for x in sys.argv if x.find("days=") == 0), None)
    num_days = int(num_days) if num_days else 365
    info_path = next((x.split("=", 1)[-1] for x in sys.argv if x.find("info=") == 0), None)
    with open(info_path, "r") as f:
        info_json = json.load(f)
    cert_path = next((x.split("=", 1)[-1] for x in sys.argv if x.find("cert=") == 0), None)
    pk, cert = create_self_signed_certificate(num_bits, num_days, info_json)
    with open(cert_path, "w") as f:
        f.write(pk)
        f.write(cert)
    print("Certificate saved to " + cert_path)

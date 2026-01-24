import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from pyasn1.codec.der import encoder

from ref_impl import sia_utils
from ref_impl import rfc_cert_discover

def create_self_signed_sia_cert(output_path="self_signed_sia_cert.der"):
    # Generate a private key for the self-signed certificate
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Subject and Issuer are the same for a self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u"Example Self-Signed Root"),
    ])

    # Build the SIA extension value using sia_utils
    # Purpose: Self, URI: http://example.authority/root.der
    purpose_uri_pairs = [
        (rfc_cert_discover.id_rcd_self, "http://example.authority/root.der")
    ]
    sia_value_asn1 = sia_utils.build_sia_extension_value(purpose_uri_pairs)
    sia_der_bytes = encoder.encode(sia_value_asn1)

    # Create the certificate
    now = datetime.datetime.utcnow()
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now
    ).not_valid_after(
        now + datetime.timedelta(days=365)
    ).add_extension(
        x509.UnrecognizedExtension(
            x509.ObjectIdentifier("1.3.6.1.5.5.7.1.11"), # id-pe-subjectInfoAccess
            sia_der_bytes
        ),
        critical=False
    ).sign(private_key, hashes.SHA256())

    # Write the certificate to a file
    with open(output_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.DER))
    
    print(f"Certificate created and saved to {output_path}")
    return cert

if __name__ == "__main__":
    create_self_signed_sia_cert()

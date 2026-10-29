import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from dilithium_py.ml_dsa import ML_DSA_65
from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder
from pyasn1.type import tag
from pyasn1.type import univ
from pyasn1.type import useful

from pyasn1_alt_modules import rfc5280


def _build_validity_asn1(not_before, not_after):
    validity = rfc5280.Validity()

    if not_before.year < 2050:
        validity["notBefore"]["utcTime"] = useful.UTCTime(not_before.strftime("%y%m%d%H%M%SZ"))
    else:
        validity["notBefore"]["generalTime"] = useful.GeneralizedTime(
            not_before.strftime("%Y%m%d%H%M%SZ")
        )

    if not_after.year < 2050:
        validity["notAfter"]["utcTime"] = useful.UTCTime(not_after.strftime("%y%m%d%H%M%SZ"))
    else:
        validity["notAfter"]["generalTime"] = useful.GeneralizedTime(
            not_after.strftime("%Y%m%d%H%M%SZ")
        )

    return validity


def _compute_ski_from_spki_der(spki_der):
    spki_asn1, rest = decoder.decode(spki_der, asn1Spec=rfc5280.SubjectPublicKeyInfo())
    if rest:
        raise ValueError("Trailing bytes when decoding SPKI DER")
    subject_public_key_bytes = spki_asn1["subjectPublicKey"].asOctets()
    digest = hashes.Hash(hashes.SHA1())
    digest.update(subject_public_key_bytes)
    return digest.finalize()


def _build_root_extensions(subject_public_key):
    return [
        x509.Extension(
            x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER,
            critical=False,
            value=x509.SubjectKeyIdentifier.from_public_key(subject_public_key),
        ),
        x509.Extension(
            x509.ExtensionOID.KEY_USAGE,
            critical=True,
            value=x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
        ),
        x509.Extension(
            x509.ExtensionOID.BASIC_CONSTRAINTS,
            critical=True,
            value=x509.BasicConstraints(ca=True, path_length=None),
        ),
    ]


def _create_self_signed_root_cert_ecdsa(common_name, subject_spki_der, signing_key):
    subject_public_key = serialization.load_der_public_key(subject_spki_der)
    if not isinstance(signing_key, ec.EllipticCurvePrivateKey):
        raise TypeError("ECDSA signing requires an EllipticCurvePrivateKey")

    subject = issuer = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(subject_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
    )

    for extension in _build_root_extensions(subject_public_key):
        builder = builder.add_extension(extension.value, critical=extension.critical)

    return builder.sign(private_key=signing_key, algorithm=hashes.SHA256())


def _create_self_signed_root_cert_ml_dsa(common_name, subject_spki_der, signing_key, ml_dsa):
    if not isinstance(signing_key, bytes):
        raise TypeError("ML-DSA signing requires packed signing key bytes")
    if getattr(ml_dsa, "oid", None) is None:
        raise ValueError("ML-DSA instance must include an OID")

    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    subject_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)])
    subject_name_asn1, rest = decoder.decode(subject_name.public_bytes(), asn1Spec=rfc5280.Name())
    if rest:
        raise ValueError("Trailing bytes when decoding Name DER")

    spki_asn1, rest = decoder.decode(subject_spki_der, asn1Spec=rfc5280.SubjectPublicKeyInfo())
    if rest:
        raise ValueError("Trailing bytes when decoding SPKI DER")

    # Build root CA extensions without SIA.
    extensions = rfc5280.Extensions().subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3)
    )

    ski_ext = rfc5280.Extension()
    ski_ext["extnID"] = rfc5280.id_ce_subjectKeyIdentifier
    ski_ext["critical"] = False
    ski_ext["extnValue"] = encoder.encode(rfc5280.SubjectKeyIdentifier(_compute_ski_from_spki_der(subject_spki_der)))
    extensions.append(ski_ext)

    key_usage_ext = rfc5280.Extension()
    key_usage_ext["extnID"] = rfc5280.id_ce_keyUsage
    key_usage_ext["critical"] = True
    key_usage_ext["extnValue"] = x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    ).public_bytes()
    extensions.append(key_usage_ext)

    basic_constraints_ext = rfc5280.Extension()
    basic_constraints_ext["extnID"] = rfc5280.id_ce_basicConstraints
    basic_constraints_ext["critical"] = True
    basic_constraints_ext["extnValue"] = x509.BasicConstraints(ca=True, path_length=None).public_bytes()
    extensions.append(basic_constraints_ext)

    signature_algorithm = rfc5280.AlgorithmIdentifier()
    signature_algorithm["algorithm"] = ml_dsa.oid

    tbs = rfc5280.TBSCertificate()
    tbs["version"] = 2
    tbs["serialNumber"] = x509.random_serial_number()
    tbs["signature"] = signature_algorithm
    tbs["issuer"] = subject_name_asn1
    tbs["validity"] = _build_validity_asn1(now, now + datetime.timedelta(days=3650))
    tbs["subject"] = subject_name_asn1
    tbs["subjectPublicKeyInfo"] = spki_asn1
    tbs["extensions"] = extensions

    tbs_der = encoder.encode(tbs)
    signature = ml_dsa.sign(signing_key, tbs_der)

    cert = rfc5280.Certificate()
    cert["tbsCertificate"] = tbs
    cert["signatureAlgorithm"] = signature_algorithm
    cert["signature"] = univ.BitString.fromOctetString(signature)

    return x509.load_der_x509_certificate(encoder.encode(cert))


def create_self_signed_root_cert(common_name, subject_spki_der, signing_key, ml_dsa=ML_DSA_65):
    """
    Create a self-signed root certificate without SIA using either ECDSA or ML-DSA.

    :param common_name: Subject/issuer common name.
    :param subject_spki_der: DER-encoded SubjectPublicKeyInfo for the certified key.
    :param signing_key: ECDSA private key object or ML-DSA packed signing key bytes.
    :param ml_dsa: ML-DSA parameter object (defaults to ML_DSA_65).
    :return: cryptography.x509.Certificate
    """
    if isinstance(signing_key, ec.EllipticCurvePrivateKey):
        return _create_self_signed_root_cert_ecdsa(common_name, subject_spki_der, signing_key)

    if isinstance(signing_key, bytes):
        return _create_self_signed_root_cert_ml_dsa(common_name, subject_spki_der, signing_key, ml_dsa)

    raise TypeError("signing_key must be an ECDSA private key or ML-DSA signing key bytes")


if __name__ == "__main__":
    ecdsa_private_key = ec.generate_private_key(ec.SECP256R1())
    cert = create_self_signed_root_cert(
        common_name="Example Self-Signed Root",
        subject_spki_der=ecdsa_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
        signing_key=ecdsa_private_key,
    )

    with open("self_signed_root_cert.der", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.DER))

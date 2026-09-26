#!/usr/bin/env python3
"""Print certificate discovery descriptors from SIA extension.

Given a PEM-encoded certificate, this script extracts Subject Information Access
entries that use the certificate discovery access method and prints each
RelatedCertificateDescriptor in text format.
"""

import argparse
import base64
from pathlib import Path

from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280

try:
    from ref_impl import rfc_cert_discover
except ImportError:
    import rfc_cert_discover


def _load_certificate(cert_path: Path) -> rfc5280.Certificate:
    raw_data = cert_path.read_bytes()
    if not raw_data:
        raise ValueError("Input certificate file is empty")

    # Detect encoding from first octet as requested:
    # 0x30 => DER SEQUENCE, otherwise treat as PEM text.
    if raw_data[0] == 0x30:
        cert_der = raw_data
    else:
        cert_der = _pem_to_der(raw_data.decode("utf-8"))

    cert, rest = decoder.decode(cert_der, asn1Spec=rfc5280.Certificate())
    if rest:
        raise ValueError("Trailing bytes found after certificate DER")
    return cert


def _pem_to_der(pem_text: str) -> bytes:
    begin = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"

    if begin not in pem_text or end not in pem_text:
        raise ValueError("Input does not contain a PEM certificate block")

    b64_lines = []
    in_cert = False
    for line in pem_text.splitlines():
        stripped = line.strip()
        if stripped == begin:
            in_cert = True
            continue
        if stripped == end:
            break
        if in_cert and stripped:
            b64_lines.append(stripped)

    if not b64_lines:
        raise ValueError("PEM certificate block is empty")

    return base64.b64decode("".join(b64_lines), validate=True)


def _der_to_pem(der_bytes: bytes, label: str = "CERTIFICATE") -> str:
    b64 = base64.b64encode(der_bytes).decode("ascii")
    chunks = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(chunks) + f"\n-----END {label}-----"


def _intent_name_map() -> dict[str, str]:
    oid_to_name = {}
    for name, value in vars(rfc_cert_discover).items():
        # Intent IDs are defined as id_rcd* constants in rfc_cert_discover.py.
        if name.startswith("id_rcd") and isinstance(value, univ.ObjectIdentifier):
            oid_to_name[str(value)] = name
    return oid_to_name


def _extract_cert_discovery_descriptors(cert: rfc5280.Certificate) -> list[rfc_cert_discover.RelatedCertificateDescriptor]:
    descriptors = []
    extensions = cert["tbsCertificate"]["extensions"]
    if not extensions.isValue:
        return descriptors

    for extension in extensions:
        if extension["extnID"] != rfc5280.id_pe_subjectInfoAccess:
            continue

        sia_der = bytes(extension["extnValue"])
        sia, rest = decoder.decode(sia_der, asn1Spec=rfc5280.SubjectInfoAccessSyntax())
        if rest:
            raise ValueError("Trailing bytes found in SubjectInfoAccess extension")

        for access_description in sia:
            if access_description["accessMethod"] != rfc_cert_discover.id_ad_certDiscovery:
                continue

            general_name = access_description["accessLocation"]
            if general_name.getName() != "otherName":
                continue

            other_name = general_name["otherName"]
            if other_name["type-id"] != rfc_cert_discover.id_on_relatedCertificateDescriptor:
                continue

            descriptor, rest = decoder.decode(
                bytes(other_name["value"]),
                asn1Spec=rfc_cert_discover.RelatedCertificateDescriptor(),
            )
            if rest:
                raise ValueError("Trailing bytes found in RelatedCertificateDescriptor")

            descriptors.append(descriptor)

    return descriptors


def _format_descriptor(descriptor: rfc_cert_discover.RelatedCertificateDescriptor, index: int, intent_names: dict[str, str]) -> str:
    lines = [f"Descriptor {index}:"]

    method = descriptor["method"]
    method_name = method.getName()

    if method_name == "byUri":
        by_uri = method["byUri"]
        lines.append("  Method: byUri")
        lines.append(f"  URI: {str(by_uri['uri'])}")

        if by_uri["certHash"].isValue:
            cert_hash = by_uri["certHash"]
            lines.append(f"  CertHash.value: {bytes(cert_hash['value']).hex()}")
            if cert_hash["hashAlgorithm"].isValue:
                lines.append(
                    f"  CertHash.hashAlgorithm: {str(cert_hash['hashAlgorithm']['algorithm'])}"
                )

    elif method_name == "byInclusion":
        included_cert = method["byInclusion"]
        included_der = encoder.encode(included_cert)
        lines.append("  Method: byInclusion")
        lines.append("  IncludedCertificatePEM:")
        lines.append(_indent(_der_to_pem(included_der), "    "))

    elif method_name == "byLocalPolicy":
        lines.append("  Method: byLocalPolicy")

    else:
        lines.append(f"  Method: {method_name}")

    intent_field = descriptor["intent"]
    if intent_field.isValue:
        intent_oid = str(intent_field)
        intent_text = intent_names.get(intent_oid, intent_oid)
        lines.append(f"  Intent: {intent_text}")

    sig_alg = descriptor["signatureAlgorithm"]
    if sig_alg.isValue:
        lines.append(f"  SignatureAlgorithm: {str(sig_alg['algorithm'])}")

    pub_alg = descriptor["publicKeyAlgorithm"]
    if pub_alg.isValue:
        lines.append(f"  PublicKeyAlgorithm: {str(pub_alg['algorithm'])}")

    return "\n".join(lines)


def _indent(text: str, prefix: str) -> str:
    return "\n".join(prefix + line for line in text.splitlines())


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Print certificate discovery descriptors from the SIA extension of a certificate "
            "(DER when first octet is 0x30, otherwise PEM)."
        )
    )
    parser.add_argument(
        "certificate",
        type=Path,
        help="Path to certificate file (DER if first octet is 0x30, else PEM)",
    )
    args = parser.parse_args()

    cert = _load_certificate(args.certificate)
    descriptors = _extract_cert_discovery_descriptors(cert)

    if not descriptors:
        print("No certificate discovery descriptors found in SIA extension.")
        return

    intent_names = _intent_name_map()
    for i, descriptor in enumerate(descriptors, start=1):
        print(_format_descriptor(descriptor, i, intent_names))
        if i != len(descriptors):
            print()


if __name__ == "__main__":
    main()

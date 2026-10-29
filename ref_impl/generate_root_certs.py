#!/usr/bin/env python3
import argparse
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from dilithium_py.ml_dsa import ML_DSA_44
from pyasn1.codec.der import encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280

from create_sia_cert import create_self_signed_root_cert


def _build_ml_dsa_spki_der(public_key: bytes, ml_dsa=ML_DSA_44) -> bytes:
    """Encode an ML-DSA public key as SubjectPublicKeyInfo DER."""
    spki = rfc5280.SubjectPublicKeyInfo()
    spki["algorithm"]["algorithm"] = univ.ObjectIdentifier(ml_dsa.oid)
    spki["subjectPublicKey"] = univ.BitString.fromOctetString(public_key)
    return encoder.encode(spki)


def generate_root_cert_pem_bundle(output_path: Path) -> None:
    # Root 1: EC P-256
    ec_common_name = "EC P256 CA"
    ec_private_key = ec.generate_private_key(ec.SECP256R1())
    ec_cert = create_self_signed_root_cert(
        common_name=ec_common_name,
        subject_spki_der=ec_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
        signing_key=ec_private_key,
    )

    # Root 2: ML-DSA-44
    mldsa_common_name = "MLDSA-44 CA"
    ml_dsa_public_key, ml_dsa_signing_key = ML_DSA_44.keygen()
    ml_dsa_cert = create_self_signed_root_cert(
        common_name=mldsa_common_name,
        subject_spki_der=_build_ml_dsa_spki_der(ml_dsa_public_key, ML_DSA_44),
        signing_key=ml_dsa_signing_key,
        ml_dsa=ML_DSA_44,
    )

    # Write each cert to its own file
    for cn, cert in [
        (ec_common_name, ec_cert),
        (mldsa_common_name, ml_dsa_cert),
    ]:
        fname = cn.replace(" ", "_") + ".pem"
        pem_path = output_path.parent / fname
        pem_path.parent.mkdir(parents=True, exist_ok=True)
        pem_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        print(f"Wrote: {pem_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate EC P-256 and ML-DSA-44 self-signed root certificates in one PEM file."
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("root_certs.pem"),
        help="Output PEM file path (default: root_certs.pem)",
    )
    args = parser.parse_args()

    generate_root_cert_pem_bundle(args.output)


if __name__ == "__main__":
    main()

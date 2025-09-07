# pdfsign.py

import io
import os
from pathlib import Path

from .config import KEY_DIR, CERT_DIR  # use your config paths

from pyhanko.sign.signers import SimpleSigner, PdfSignatureMetadata
from pyhanko.sign import signers
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.fields import SigFieldSpec, append_signature_field
from pyhanko.sign.validation import async_validate_pdf_signature
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko_certvalidator import ValidationContext

from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import serialization
from asn1crypto import x509 as asn1_x509


# File locations inside your folders
KEY_PATH = KEY_DIR / "private_key.pem"
CERT_PATH = CERT_DIR / "certificate.pem"


def ensure_cert_files():
    """
    Ensure PEM key/cert files exist locally.
    - Uses Railway env vars PRIVATE_KEY_PEM and CERTIFICATE_PEM if provided.
    - Falls back to files in keys/ and certificates/ if present.
    """
    priv_data = os.getenv("PRIVATE_KEY_PEM")
    cert_data = os.getenv("CERTIFICATE_PEM")

    if priv_data and not KEY_PATH.exists():
        KEY_PATH.write_text(priv_data)
    if cert_data and not CERT_PATH.exists():
        CERT_PATH.write_text(cert_data)

    if not KEY_PATH.exists() or not CERT_PATH.exists():
        raise RuntimeError("Key or cert missing. Provide via env or local files.")

    return KEY_PATH, CERT_PATH


def load_simple_signer():
    """Load a SimpleSigner using the available key/cert."""
    key_path, cert_path = ensure_cert_files()
    return SimpleSigner.load(
        key_file=key_path,
        cert_file=cert_path,
        ca_chain_files=None,
        key_passphrase=None,
    )


def sign_pdf_with_pyhanko(input_pdf_path: str, output_pdf_path: str):
    """Sign a PDF using pyHanko and save to output path."""
    signer = load_simple_signer()
    with open(input_pdf_path, "rb") as f:
        data = f.read()

    writer = IncrementalPdfFileWriter(io.BytesIO(data))

    # Add a visible signature field
    append_signature_field(
        writer,
        sig_field_spec=SigFieldSpec(sig_field_name="Signature1", box=(50, 50, 250, 120)),
    )

    meta = PdfSignatureMetadata(
        field_name="Signature1",
        reason="Wipe Certificate",
        location="SecureWipe",
    )
    pdf_signer = signers.PdfSigner(meta, signer=signer)

    out = io.BytesIO()
    pdf_signer.sign_pdf(writer, output=out)

    with open(output_pdf_path, "wb") as f:
        f.write(out.getvalue())


async def verify_pdf_signed_by_our_key(pdf_bytes: bytes, signer_cert_pem_path: str) -> dict:
    """
    Verify a PDF's signature against our signer certificate.
    Returns a dict {valid: bool, coverage: str}.
    """
    with open(signer_cert_pem_path, "rb") as f:
        pem = f.read()

    # Load cert into cryptography + asn1crypto objects
    crypto_cert = crypto_x509.load_pem_x509_certificate(pem)
    cert_der = crypto_cert.public_bytes(serialization.Encoding.DER)
    cert_obj = asn1_x509.Certificate.load(cert_der)

    vc = ValidationContext(trust_roots=[cert_obj])
    reader = PdfFileReader(io.BytesIO(pdf_bytes))

    if not reader.embedded_signatures:
        return {"valid": False, "reason": "no signatures"}

    sig = reader.embedded_signatures[0]
    v = await async_validate_pdf_signature(sig, vc)
    return {"valid": v.trusted, "coverage": str(v.coverage)}

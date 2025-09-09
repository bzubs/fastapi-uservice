# pdfsign.py
import io
import os
import tempfile
from pathlib import Path

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

from dotenv import load_dotenv

load_dotenv()


def _write_env_pems_to_tempfiles() -> tuple[str, str, tempfile.TemporaryDirectory]:
    """
    Write PRIVATE_KEY_PEM and CERTIFICATE_PEM env vars to files inside a TemporaryDirectory.
    Returns (priv_path_str, cert_path_str, tmpdir_obj).
    Caller is responsible for calling tmpdir_obj.cleanup() when done (or using the tmpdir context manager).
    """
    priv_data = os.getenv("PRIVATE_KEY_PEM")
    cert_data = os.getenv("CERTIFICATE_PEM")

    if not priv_data or not cert_data:
        raise RuntimeError("Missing PRIVATE_KEY_PEM or CERTIFICATE_PEM environment variables")

    tmpdir = tempfile.TemporaryDirectory()
    tmpdir_path = Path(tmpdir.name)
    priv_path = tmpdir_path / "private_key.pem"
    cert_path = tmpdir_path / "certificate.pem"

    # Write exact PEM bytes (no sanitization)
    priv_path.write_bytes(priv_data.encode("utf-8"))
    cert_path.write_bytes(cert_data.encode("utf-8"))

    # Best-effort permission restriction on POSIX
    try:
        os.chmod(priv_path, 0o600)
    except Exception:
        # ignore on systems that don't support chmod (Windows, etc.)
        pass

    return str(priv_path), str(cert_path), tmpdir


def load_simple_signer(remove_temp=True) -> SimpleSigner:
    """
    Create a SimpleSigner by writing env PEMs to a temporary directory and calling SimpleSigner.load().
    remove_temp=True will cleanup the temporary directory after loading the signer.
    """
    priv_file, cert_file, tmpdir = _write_env_pems_to_tempfiles()

    try:
        signer = SimpleSigner.load(
            key_file=priv_file,
            cert_file=cert_file,
            ca_chain_files=None,
            key_passphrase=None,
        )
    except Exception as e:
        # include file paths in the message for easier debugging (but don't include key contents)
        # ensure temp directory cleaned up before raising
        try:
            tmpdir.cleanup()
        except Exception:
            pass
        raise RuntimeError(f"Failed to load SimpleSigner from files ({priv_file}, {cert_file}): {e}") from e

    # cleanup the tempdir if requested (SimpleSigner.load reads files into memory)
    if remove_temp:
        try:
            tmpdir.cleanup()
        except Exception:
            pass

    return signer


def sign_pdf(input_pdf: io.BytesIO) -> io.BytesIO:
    """
    Sign a PDF in-memory using pyHanko and the certificate/private key loaded from env.
    Args:
        input_pdf: BytesIO object containing the unsigned PDF.
    Returns:
        BytesIO object containing the signed PDF.
    """
    signer = load_simple_signer(remove_temp=True)

    # ensure buffer position
    input_pdf.seek(0)
    writer = IncrementalPdfFileWriter(input_pdf)

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
    out.seek(0)
    return out


async def verify_pdf_signed_by_our_key(pdf_bytes: bytes) -> dict:
    """
    Verify a PDF's signature against our signer certificate (from env).
    Returns a dict with verification results.
    """
    cert_data = os.getenv("CERTIFICATE_PEM")
    if not cert_data:
        return {"valid": False, "reason": "Missing CERTIFICATE_PEM env var"}

    pem = cert_data.encode("utf-8")

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

import datetime
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from endesive.pdf import cms
import hashlib

# Cargar clave privada
with open("user_key.pem", "rb") as f:
    user_key = serialization.load_pem_private_key(f.read(), password=b"qazwsx")

# Cargar certificado de usuario
with open("user_cert.pem", "rb") as f:
    user_cert = x509.load_pem_x509_certificate(f.read())

# Cargar CA
with open("ca_cert.pem", "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read())

# Parámetros de firma
date = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S+00'00'")
dct = {
    "sigflags": 3,
    "sigpage": 0,
    "sigbutton": True,
    "contact": "fencisoq@uni.pe",
    "location": "Lima, Peru",
    "signingdate": date.encode(),
    "reason": "Certificacion de documento academico",
    "signature": "Frey Enciso",
}

# Leer PDF
with open("CD.pdf", "rb") as f:
    pdf_data = f.read()

print("[ 1/2 ] Firmando PDF...")

# Firmar
signed_data = cms.sign(
    pdf_data,
    dct,
    user_key,
    user_cert,
    [ca_cert],
    "sha256",
)

# Guardar PDF firmado
with open("CD_firmado.pdf", "wb") as f:
    f.write(pdf_data)
    f.write(signed_data)

print("[ 2/2 ] PDF firmado guardado.")
print()
print("=" * 40)
print("  Archivo generado: CD_firmado.pdf")
print("=" * 40)
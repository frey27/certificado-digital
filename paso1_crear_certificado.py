from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timezone, timedelta

# CA raíz
print("[ 1/4 ] Generando claves CA...")
ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

ca_name = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "PE"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Lima"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UNI-FIIS"),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "SI904U"),
    x509.NameAttribute(NameOID.COMMON_NAME, "UNI-FIIS CA Raiz"),
])

print("[ 2/4 ] Creando certificado CA...")
ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_name)
    .issuer_name(ca_name)
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.now(timezone.utc))
    .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(ca_key, hashes.SHA256())
)

with open("ca_cert.pem", "wb") as f:
    f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
print("    -> ca_cert.pem OK")

# Certificado de usuario
print("[ 3/4 ] Generando claves de usuario...")
user_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

user_name = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "PE"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Lima"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UNI-FIIS"),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "SI904V"),
    x509.NameAttribute(NameOID.COMMON_NAME, "Frey Enciso"),
    x509.NameAttribute(NameOID.EMAIL_ADDRESS, "fencisoq@uni.pe"),
])

print("[ 4/4 ] Firmando certificado de usuario...")
user_cert = (
    x509.CertificateBuilder()
    .subject_name(user_name)
    .issuer_name(ca_name)
    .public_key(user_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.now(timezone.utc))
    .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .sign(ca_key, hashes.SHA256())
)

with open("user_cert.pem", "wb") as f:
    f.write(user_cert.public_bytes(serialization.Encoding.PEM))

with open("user_key.pem", "wb") as f:
    f.write(user_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(b"qazwsx")
    ))

print("    -> user_cert.pem OK")
print("    -> user_key.pem  OK")
print()
print("=" * 40)
print("  Certificados generados.")
print("  Clave privada pass: qazwsx")
print("=" * 40)
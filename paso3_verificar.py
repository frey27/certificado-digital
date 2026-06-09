from cryptography import x509
from cryptography.hazmat.primitives import serialization

print("Iniciando...")

# Datos del certificado
with open("user_cert.pem", "rb") as f:
    user_cert = x509.load_pem_x509_certificate(f.read())

print("Certificado cargado OK")

with open("ca_cert.pem", "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read())

print("CA cargada OK")

with open("CD_firmado.pdf", "rb") as f:
    pdf_data = f.read()

print(f"PDF cargado OK - tamaño: {len(pdf_data)} bytes")

print()
print("=" * 45)
print("  CERTIFICADO DIGITAL")
print("=" * 45)
print(f"  Titular      : {user_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value}")
print(f"  Email        : {user_cert.subject.get_attributes_for_oid(x509.oid.NameOID.EMAIL_ADDRESS)[0].value}")
print(f"  Org          : {user_cert.subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)[0].value}")
print(f"  Emisor       : {user_cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value}")
print(f"  Válido desde : {user_cert.not_valid_before_utc.strftime('%d/%m/%Y')}")
print(f"  Válido hasta : {user_cert.not_valid_after_utc.strftime('%d/%m/%Y')}")
print(f"  Nro. Serie   : {user_cert.serial_number}")
print(f"  Algoritmo    : {user_cert.signature_hash_algorithm.name.upper()} con RSA")
print("=" * 45)

print()
print("Verificando firma...")

try:
    from endesive.pdf import verify as verify_pdf
    signatures = verify_pdf(pdf_data, [ca_cert.public_bytes(serialization.Encoding.PEM)])
    print(f"Firmas encontradas: {signatures}")
    if signatures:
        print("  FIRMA DIGITAL: VÁLIDA ✓")
    else:
        print("  No se encontraron firmas.")
except Exception as e:
    import traceback
    print(f"Error: {e}")
    traceback.print_exc()
# Certificado Digital con Python

**Curso:** Seguridad de Sistemas — SI904U
**Alumno:** Frey Enciso
**Fecha:** 09/06/2026

---

## ¿Qué hicimos?

Creamos un certificado digital desde cero usando Python y lo usamos para firmar un documento PDF. La idea es parecida a lo que hace RENIEC cuando te da un certificado digital — una entidad (la autoridad certificadora) avala tu identidad, y con ese aval puedes firmar documentos.

Al final del ejercicio logramos:

- Una autoridad certificadora propia
- Un certificado digital a nombre de Frey Enciso
- Un PDF firmado digitalmente con ese certificado

---

## Herramientas que usamos

- **Python 3.14.2**
- **VSCode** como editor
- **Librería `cryptography`** — para crear el certificado
- **Librería `endesive`** — para firmar el PDF
- **Librería `pypdf`** — para manejar archivos PDF

---

## Paso 1 — Preparar el entorno

Primero creamos una carpeta llamada `Certificado Digital` y la abrimos en VSCode. Dentro de esa carpeta creamos un entorno virtual para instalar las librerías sin afectar el resto del sistema.

```bash
python -m venv venv --without-pip
```

Activamos el entorno virtual:

```bash
venv\Scripts\activate
```

Instalamos las librerías necesarias:

```bash
.\venv\Scripts\pip3.exe install cryptography
.\venv\Scripts\pip3.exe install pypdf reportlab endesive --no-deps
.\venv\Scripts\pip3.exe install asn1crypto lxml requests
```

También copiamos nuestro documento `CD.pdf` dentro de la carpeta del proyecto.

---

## Paso 2 — Crear el certificado digital

Creamos el archivo `paso1_crear_certificado.py`. Este script hace dos cosas:

1. Crea una **autoridad certificadora** (la entidad que avala identidades)
2. Crea el **certificado de Frey Enciso**, firmado por esa autoridad

```python
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
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "SI904V"),
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
```

Lo ejecutamos con:

```bash
.\venv\Scripts\python.exe paso1_crear_certificado.py
```

El resultado fue:

```
[ 1/4 ] Generando claves CA...
[ 2/4 ] Creando certificado CA...
    -> ca_cert.pem OK
[ 3/4 ] Generando claves de usuario...
[ 4/4 ] Firmando certificado de usuario...
    -> user_cert.pem OK
    -> user_key.pem  OK
========================================
  Certificados generados.
  Clave privada pass: qazwsx
========================================
```

Esto generó tres archivos nuevos en la carpeta:

| Archivo           | Qué contiene                                               |
| ----------------- | ----------------------------------------------------------- |
| `ca_cert.pem`   | El certificado de la autoridad certificadora                |
| `user_cert.pem` | El certificado digital de Frey Enciso                       |
| `user_key.pem`  | La clave privada de Frey Enciso (protegida con contraseña) |

---

## Paso 3 — Firmar el PDF

Creamos el archivo `paso2_firmar_pdf.py`. Este script toma el archivo `CD.pdf` y le incrusta la firma digital usando el certificado que creamos antes.

```python
import datetime
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from endesive.pdf import cms

with open("user_key.pem", "rb") as f:
    user_key = serialization.load_pem_private_key(f.read(), password=b"qazwsx")

with open("user_cert.pem", "rb") as f:
    user_cert = x509.load_pem_x509_certificate(f.read())

with open("ca_cert.pem", "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read())

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

with open("CD.pdf", "rb") as f:
    pdf_data = f.read()

print("[ 1/2 ] Firmando PDF...")

signed_data = cms.sign(
    pdf_data,
    dct,
    user_key,
    user_cert,
    [ca_cert],
    "sha256",
)

with open("CD_firmado.pdf", "wb") as f:
    f.write(pdf_data)
    f.write(signed_data)

print("[ 2/2 ] PDF firmado guardado.")
print()
print("=" * 40)
print("  Archivo generado: CD_firmado.pdf")
print("=" * 40)
```

Lo ejecutamos con:

```bash
.\venv\Scripts\python.exe paso2_firmar_pdf.py
```

El resultado fue:

```
[ 1/2 ] Firmando PDF...
[ 2/2 ] PDF firmado guardado.
========================================
  Archivo generado: CD_firmado.pdf
========================================
```

Esto generó el archivo `CD_firmado.pdf` con la firma digital incrustada.

---

## Paso 4 — Verificar la firma

Creamos el archivo `paso3_verificar.py` para confirmar que la firma quedó correctamente en el PDF y mostrar los datos del certificado.

```python
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from endesive.pdf import verify as verify_pdf

print("Iniciando...")

with open("user_cert.pem", "rb") as f:
    user_cert = x509.load_pem_x509_certificate(f.read())

with open("ca_cert.pem", "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read())

with open("CD_firmado.pdf", "rb") as f:
    pdf_data = f.read()

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

signatures = verify_pdf(pdf_data, [ca_cert.public_bytes(serialization.Encoding.PEM)])
if signatures:
    print("  FIRMA DIGITAL: VÁLIDA ✓")
```

Lo ejecutamos con:

```bash
.\venv\Scripts\python.exe paso3_verificar.py
```

El resultado fue:

```
=============================================
  CERTIFICADO DIGITAL
=============================================
  Titular      : Frey Enciso
  Email        : fencisoq@uni.pe
  Org          : UNI-FIIS
  Emisor       : UNI-FIIS CA Raiz
  Válido desde : 09/06/2026
  Válido hasta : 09/06/2027
  Nro. Serie   : 137592230911678359046258972517793920892167777328
  Algoritmo    : SHA256 con RSA
=============================================
Verificando firma...
  FIRMA DIGITAL: VÁLIDA ✓
```

---

## Archivos generados al final

```
Certificado Digital/
├── paso1_crear_certificado.py
├── paso2_firmar_pdf.py
├── paso3_verificar.py
├── ca_cert.pem
├── user_cert.pem
├── user_key.pem
├── CD.pdf
└── CD_firmado.pdf
```

---

## ¿Qué aprendimos?

- Un certificado digital tiene datos del titular, del emisor, fechas de validez y un algoritmo de firma.
- La clave privada es personal y se protege con contraseña — nunca se comparte.
- La firma digital garantiza que el documento no fue modificado después de firmarse.
- Para que una firma sea reconocida mundialmente, la autoridad certificadora debe ser pública y registrada (como RENIEC). La nuestra es local, por eso solo es válida dentro de nuestro ejercicio.

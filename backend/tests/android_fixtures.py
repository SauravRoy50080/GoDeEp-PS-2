"""Original synthetic fixtures: compiled XML chunks and unverified signing containers.

No malware, SDK binaries or third-party APKs are distributed. These fixtures test
parser contracts, not installability or cryptographic Android signature validity.
"""

import io
import struct
from datetime import UTC, datetime, timedelta
from zipfile import ZIP_DEFLATED, ZipFile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID
from lxml import etree

URI = "http://schemas.android.com/apk/res/android"
MANIFEST = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
 package="org.godeep.fixture" android:versionCode="7" android:versionName="1.2">
 <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="33"/>
 <uses-permission android:name="android.permission.READ_SMS" android:maxSdkVersion="32"/>
 <uses-permission android:name="android.permission.INTERNET"/>
 <permission android:name="org.godeep.fixture.PRIVATE" android:protectionLevel="signature"/>
 <application android:label="@string/app_name" android:debuggable="true"
  android:allowBackup="true" android:usesCleartextTraffic="true">
  <activity android:name=".MainActivity" android:exported="true">
   <intent-filter><action android:name="android.intent.action.MAIN"/>
    <category android:name="android.intent.category.LAUNCHER"/></intent-filter>
  </activity>
  <service android:name="SyncService" android:exported="true"/>
  <receiver android:name=".PrivateReceiver" android:exported="false"/>
  <provider android:name=".DataProvider" android:authorities="org.godeep.fixture.data"/>
 </application>
</manifest>"""


def binary_manifest(xml=MANIFEST):
    tree = etree.fromstring(xml.encode())
    strings = ["android", URI]

    def index(value):
        if value not in strings:
            strings.append(value)
        return strings.index(value)

    for node in tree.iter():
        index(node.tag)
        for key, value in node.attrib.items():
            index(key.split("}")[-1])
            index(value)

    def length(value):
        return bytes([value]) if value < 128 else bytes([0x80 | (value >> 8), value & 255])

    offsets, encoded = [], b""
    for value in strings:
        offsets.append(len(encoded))
        raw = value.encode("utf-8")
        encoded += length(len(value.encode("utf-16-le")) // 2) + length(len(raw)) + raw + b"\0"
    encoded += b"\0" * (-len(encoded) % 4)
    string_pool = struct.pack(
        "<HHI5I",
        1,
        28,
        28 + len(offsets) * 4 + len(encoded),
        len(strings),
        0,
        0x100,
        28 + len(offsets) * 4,
        0,
    )
    string_pool += b"".join(struct.pack("<I", n) for n in offsets) + encoded

    def chunk(kind, body):
        return struct.pack("<HHIII", kind, 16, 16 + len(body), 1, 0xFFFFFFFF) + body

    namespace = struct.pack("<II", index("android"), index(URI))
    output = string_pool + chunk(0x100, namespace)

    def visit(node):
        attributes = b""
        for key, value in node.attrib.items():
            ns = index(URI) if key.startswith("{" + URI + "}") else 0xFFFFFFFF
            attributes += struct.pack(
                "<IIIHBBI", ns, index(key.split("}")[-1]), index(value), 8, 0, 3, index(value)
            )
        body = (
            struct.pack("<II6H", 0xFFFFFFFF, index(node.tag), 20, 20, len(node.attrib), 0, 0, 0)
            + attributes
        )
        encoded_node = chunk(0x102, body)
        for child in node:
            encoded_node += visit(child)
        return encoded_node + chunk(0x103, struct.pack("<II", 0xFFFFFFFF, index(node.tag)))

    output += visit(tree) + chunk(0x101, namespace)
    return struct.pack("<HHI", 3, 8, 8 + len(output)) + output


def certificate():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "GoDeEp synthetic certificate")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=10))
        .sign(key, hashes.SHA256())
    )
    return key, cert


def fixture_apk(manifest=None, v1=False, signing_scheme=None):
    manifest = binary_manifest() if manifest is None else manifest
    key, cert = certificate()
    buffer = io.BytesIO()
    with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr("classes.dex", "synthetic placeholder, not executable DEX")
        if v1:
            bundle = (
                pkcs7.PKCS7SignatureBuilder()
                .set_data(b"not a JAR manifest")
                .add_signer(cert, key, hashes.SHA256())
                .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])
            )
            archive.writestr("META-INF/FIXTURE.EC", bundle)
    raw = buffer.getvalue()
    if signing_scheme is None:
        return raw, cert

    def lp(value):
        return struct.pack("<I", len(value)) + value

    der = cert.public_bytes(serialization.Encoding.DER)
    ranges = struct.pack("<II", 28, 0x7FFFFFFF) if signing_scheme != "v2" else b""
    signed_data = lp(b"") + lp(lp(der)) + ranges + lp(b"")
    public_key = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    signer = lp(signed_data) + ranges + lp(b"") + lp(public_key)
    value = lp(lp(signer))
    block_id = {"v2": 0x7109871A, "v3": 0xF05368C0, "v31": 0x1B93AD61, "v31_only": 0x1B93AD61}[
        signing_scheme
    ]
    pair = struct.pack("<QI", len(value) + 4, block_id) + value
    if signing_scheme == "v31":
        pair = struct.pack("<QI", len(value) + 4, 0xF05368C0) + value + pair
    size = len(pair) + 24
    block = struct.pack("<Q", size) + pair + struct.pack("<Q", size) + b"APK Sig Block 42"
    eocd = raw.rfind(b"PK\x05\x06")
    central = struct.unpack_from("<I", raw, eocd + 16)[0]
    patched = bytearray(raw[:central] + block + raw[central:])
    struct.pack_into("<I", patched, eocd + len(block) + 16, central + len(block))
    return bytes(patched), cert

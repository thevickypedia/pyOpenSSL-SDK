import binascii
import getpass
import json
import os
import socket
from typing import List
from urllib.error import URLError, HTTPError
from urllib.request import urlopen

from OpenSSL import crypto

try:
    IP_INFO = json.load(urlopen('http://ipinfo.io/json')) or json.load(urlopen('http://ip.jsontest.com'))
except (json.JSONDecodeError, HTTPError, URLError):
    IP_INFO = {}


def _get_serial() -> bytes:
    """Generates a serial number for the self-signed SSL.

    See Also:
        - Serial Number is a unique identifier assigned by the CA which issued the certificate.

    Returns:
        bytes:
        Encoded serial number for the certificate.
    """
    serial_hex = binascii.hexlify(os.urandom(18)).decode().upper()
    return " ".join(serial_hex[i:i + 2] for i in range(0, len(serial_hex), 2)).encode('UTF-8')


def _generate_serial_hash(byte_size: int = 18, int_size: int = 36) -> int:
    """Generates a hashed serial number.

    Args:
        byte_size: Size of the bytes object containing random bytes.
        int_size: Size of the base int.

    Returns:
        int:
        Returns the hashed serial.
    """
    return int(binascii.hexlify(os.urandom(byte_size)).decode().upper(), int_size)


def generate_cert(common_name: str,
                  san_list: List[str] = None,
                  validity_in_days: int = 365,
                  country_name: str = IP_INFO.get('country', 'US'),
                  locality_name: str = IP_INFO.get('city', 'New York'),
                  state_or_province_name: str = IP_INFO.get('region', 'New York'),
                  email_address: str = None,
                  organization: str = None,
                  organization_unit_name: str = "Information Technology",
                  key_file: str = "private_key.pem",
                  cert_file: str = "certificate.pem",
                  bundle: str = None,
                  key_size: int = 2048) -> None:
    """Creates a self-signed certificate.

    Args:
        common_name: DNS name of the origin.
        san_list: List of Subject Alternative Names (SANs).
        validity_in_days: Number of days the certificate should be valid.
        country_name: Name of the country. Defaults to ``US``
        locality_name: Name of the city. Defaults to ``New York``
        state_or_province_name: Name of the state/province. Defaults to ``New York``
        email_address: Email address for the certificate. Defaults to ``user@hostname``
        organization: Organization name. Defaults to a section of the common name.
        organization_unit_name: Name of the organization unit.
        key_file: Name of the key file.
        cert_file: Name of the certificate.
        bundle: Name of the bundle file with certificate and private key embedded in it.
        key_size: Size of the public key. Defaults to 2048.

    See Also:
        Use ``openssl x509 -inform pem -in cert.crt -noout -text`` to look at the generated cert using OpenSSL.
    """
    if key_size not in (2048, 4096):
        raise ValueError('Certificate key size should be either 2048 or 4096.')
    signature_bytes = 256 if key_size == 2048 else 512

    # Creates a key pair
    key = crypto.PKey()
    key.generate_key(type=crypto.TYPE_RSA, bits=key_size)

    # Creates a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = country_name
    cert.get_subject().ST = state_or_province_name
    cert.get_subject().L = locality_name
    cert.get_subject().O = organization or common_name[0].upper() + common_name.partition('.')[0][1:]  # noqa: E741
    cert.get_subject().OU = organization_unit_name
    cert.get_subject().CN = common_name
    cert.get_subject().emailAddress = email_address or f"{getpass.getuser()}@{socket.gethostname()}"
    cert.set_serial_number(serial=cert.get_serial_number() or _generate_serial_hash())
    cert.gmtime_adj_notBefore(amount=0)
    cert.gmtime_adj_notAfter(amount=validity_in_days * 24 * 60 * 60)

    if san_list:
        san_list = [san if san.startswith('DNS:') else f"DNS:{san}" for san in san_list]
        san_extension = crypto.X509Extension(
            b'subjectAltName', False, ', '.join(san_list).encode('utf-8')
        )
        cert.add_extensions([san_extension])

    cert.set_issuer(issuer=cert.get_subject())
    cert.set_pubkey(pkey=key)
    cert.sign(pkey=key, digest=f'sha{signature_bytes}')

    with open(cert_file, "wb") as f:
        f.write(crypto.dump_certificate(type=crypto.FILETYPE_PEM, cert=cert))
        f.flush()
    with open(key_file, "wb") as f:
        f.write(crypto.dump_privatekey(type=crypto.FILETYPE_PEM, pkey=key))
        f.flush()
    if bundle:
        with (open(cert_file, 'rb') as public_file,
              open(key_file, 'rb') as private_file,
              open(bundle, 'wb') as output_file):
            output_file.write(public_file.read() + private_file.read())
            output_file.flush()

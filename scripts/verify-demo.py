from __future__ import annotations

import json
import sys
from pathlib import Path

from cryptography import x509

value = json.loads(Path(sys.argv[1]).read_text())
assert value["mode"] == "synthetic-offline"
assert value["evidence"]["integrity"] == "verified_local_chain"
assert len(value["tls_demo"]["checks"]) == 10 and all(value["tls_demo"]["checks"].values())
issued = value["transcript"][3]["result"]
certificate = x509.load_pem_x509_certificate(issued["certificate_pem"].encode())
assert certificate.serial_number == int(issued["serial"])
crl = x509.load_pem_x509_crl(value["transcript"][6]["result"]["crl_pem"].encode())
assert crl.get_revoked_certificate_by_serial_number(certificate.serial_number) is not None
assert value["transcript"][5]["expected_denial"] == 403
print("Certificate, revocation and actual TLS semantic evidence verified")

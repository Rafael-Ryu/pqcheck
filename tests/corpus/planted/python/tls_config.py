"""Planted fixture: legacy TLS/SSL protocol constants (B1).

Every reference below is a known-detectable protocol constant (see
tests/corpus/planted/expected.yaml). Not real code — do not import.
"""

import ssl

protocol_tlsv1 = ssl.PROTOCOL_TLSv1
protocol_tlsv1_1 = ssl.PROTOCOL_TLSv1_1
protocol_sslv3 = ssl.PROTOCOL_SSLv3
tlsversion_tlsv1 = ssl.TLSVersion.TLSv1
tlsversion_tlsv1_1 = ssl.TLSVersion.TLSv1_1
tlsversion_sslv3 = ssl.TLSVersion.SSLv3

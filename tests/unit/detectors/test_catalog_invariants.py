"""Invariants that keep the symbol catalog and the QuantumRisk map in sync.

These guard a silent-drift class: a canonical name added to the catalog but
not to _QUANTUM_MAP would make CryptoFinding.quantum_risk return UNKNOWN with
no failing test. The hashlib.new table is derived from the catalog, so a
direct/string-dispatch mismatch is also caught here.
"""

from pqcheck.detectors.algorithms import (
    _GO_SYMBOLS,
    CIPHER_WRAPPER,
    emittable_canonicals,
    hashlib_new_table,
    lookup_python_symbol,
)
from pqcheck.models import _QUANTUM_MAP, QuantumRisk


def test_every_emittable_canonical_has_a_quantum_risk() -> None:
    missing = {c for c in emittable_canonicals() if c.upper() not in _QUANTUM_MAP}
    assert missing == set(), f"canonicals missing from _QUANTUM_MAP: {sorted(missing)}"


def test_cipher_wrapper_marker_is_not_emittable() -> None:
    assert CIPHER_WRAPPER not in emittable_canonicals()


def test_quantum_map_classifies_emittable_canonicals_deterministically() -> None:
    # No emittable canonical may resolve to UNKNOWN through the map.
    for canonical in emittable_canonicals():
        assert _QUANTUM_MAP[canonical.upper()] is not QuantumRisk.UNKNOWN


def test_hashlib_new_table_derives_from_catalog() -> None:
    table = hashlib_new_table()
    # The suffix keys must match the canonical the direct hashlib.<name> call
    # resolves to — proving the string-dispatch path shares the catalog.
    for suffix, hit in table.items():
        assert lookup_python_symbol(f"hashlib.{suffix}") == hit
    assert set(table) == {
        "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
        "sha3_256", "sha3_384", "sha3_512", "blake2b", "blake2s",
    }


def test_go_catalog_canonicals_have_quantum_risk() -> None:
    # Every Go symbol's canonical must classify through _QUANTUM_MAP, never UNKNOWN.
    for hit in _GO_SYMBOLS.values():
        assert hit.canonical.upper() in _QUANTUM_MAP, hit.canonical
        assert _QUANTUM_MAP[hit.canonical.upper()] is not QuantumRisk.UNKNOWN

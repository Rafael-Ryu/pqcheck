"""CycloneDX 1.6 CBOM emission and validation.

Import `validate_cyclonedx_16` from `pqcheck.cbom.validator` directly —
re-exporting it here would make `python -m pqcheck.cbom.validator` (the
CI gate entrypoint) trip runpy's double-import warning.
"""

from pqcheck.cbom.builder import build_cbom

__all__ = ["build_cbom"]

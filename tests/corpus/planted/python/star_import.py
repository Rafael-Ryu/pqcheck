"""Planted fixture: star-import fallback path (reduced confidence 0.7).

Not real code — do not import. See tests/corpus/planted/expected.yaml.
"""

from hashlib import *  # noqa: F403

digest = md5(b"x")  # noqa: F405, S324

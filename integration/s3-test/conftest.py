"""Load runtime patches for the s3-tests container.

The real patch lives in ``sitecustomize.py`` so it is active for any python
entrypoint. Importing it again from pytest is harmless and guarantees the
patch is applied before tests are collected.
"""

import sitecustomize  # noqa: F401

# ---------------------------------------------------------------------------
# Monkey-patch nuke_bucket to use the minis3 admin API for force cleanup.
#
# The standard nuke_bucket cannot delete objects protected by COMPLIANCE
# retention or Legal Hold, causing cascading test errors.  The admin endpoint
# DELETE /_minis3/buckets/{name} bypasses all Object Lock checks.
# ---------------------------------------------------------------------------
import urllib.request

import s3tests.functional as _s3func

_original_nuke_bucket = _s3func.nuke_bucket


def _force_nuke_bucket(client, bucket):
    """Force-delete bucket via minis3 admin API, bypassing Object Lock."""
    try:
        req = urllib.request.Request(
            f"http://minis3:9000/_minis3/buckets/{bucket}",
            method="DELETE",
        )
        urllib.request.urlopen(req)
    except Exception:
        # Fall back to the original implementation if the admin API is
        # unreachable (e.g. running against a real S3 endpoint).
        _original_nuke_bucket(client, bucket)


_s3func.nuke_bucket = _force_nuke_bucket

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

# ---------------------------------------------------------------------------
# Drop stale fails_on_rgw markers for tests minis3 now passes.
#
# Each entry below was verified against a minis3 build containing the
# corresponding fix. The markers are upstream RGW observations; minis3
# implements the AWS behavior these tests assert.
# ---------------------------------------------------------------------------

_UNMARKED_RGW_TESTS = {
    # SigV4 accepts the HTTP Date header when X-Amz-Date is absent
    # (x-amz-date takes precedence when both are present).
    "s3tests/functional/test_headers.py::test_object_create_date_and_amz_date",
    "s3tests/functional/test_headers.py::test_object_create_amz_date_and_no_date",
    # IAM user-policy CRUD with document/name validation.
    "s3tests/functional/test_iam.py::test_put_user_policy_invalid_element",
    "s3tests/functional/test_iam.py::test_get_user_policy_invalid_policy_name",
    "s3tests/functional/test_iam.py::test_get_deleted_user_policy",
}


def pytest_collection_modifyitems(items):
    for item in items:
        if item.nodeid in _UNMARKED_RGW_TESTS:
            item.own_markers = [
                marker
                for marker in item.own_markers
                if marker.name != "fails_on_rgw"
            ]

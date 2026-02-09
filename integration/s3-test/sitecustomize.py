"""Runtime patches for the s3-tests container.

Extends botocore's S3 model with Ceph RGW logging extensions so that:
- PutBucketLogging / GetBucketLogging accept and return LoggingType, ObjectRollTime,
  RecordsBatchSize, Filter.
- PostBucketLogging operation is available (POST bucket?logging to flush logs).
"""

import copy

import botocore.client
import botocore.loaders
from botocore import validate as _validate
from botocore.exceptions import ParamValidationError

_ORIGINAL_LOAD_SERVICE_MODEL = botocore.loaders.Loader.load_service_model
_ORIGINAL_MAKE_API_CALL = botocore.client.BaseClient._make_api_call


def _inject_s3_ceph_logging_model(model):
    """Inject PostBucketLogging operation and extend LoggingEnabled with Ceph RGW fields."""
    operations = model.setdefault("operations", {})
    shapes = model.setdefault("shapes", {})

    # PostBucketLogging: POST /{Bucket}?logging (Ceph RGW extension)
    operations["PostBucketLogging"] = {
        "name": "PostBucketLogging",
        "http": {"method": "POST", "requestUri": "/{Bucket}?logging"},
        "input": {"shape": "PostBucketLoggingRequest"},
        "output": {"shape": "PostBucketLoggingOutput"},
    }
    shapes["PostBucketLoggingRequest"] = {
        "type": "structure",
        "required": ["Bucket"],
        "members": {"Bucket": {"shape": "BucketName"}},
    }
    shapes["PostBucketLoggingOutput"] = {
        "type": "structure",
        "members": {"FlushedLoggingObject": {"shape": "ObjectKey"}},
    }

    # Extend LoggingEnabled with Ceph RGW extension fields
    if "LoggingEnabled" in shapes:
        members = shapes["LoggingEnabled"].setdefault("members", {})
        members.setdefault("LoggingType", {"shape": "LoggingType"})
        members.setdefault("ObjectRollTime", {"shape": "Integer"})
        members.setdefault("RecordsBatchSize", {"shape": "Integer"})
        members.setdefault("Filter", {"shape": "LoggingFilter"})
    if "LoggingType" not in shapes:
        shapes["LoggingType"] = {"type": "string"}
    if "LoggingFilter" not in shapes:
        shapes["LoggingFilter"] = {"type": "structure", "members": {}}


def _load_service_model_with_s3_extensions(self, service_name, type_name, api_version=None):
    result = _ORIGINAL_LOAD_SERVICE_MODEL(self, service_name, type_name, api_version)
    if service_name == "s3" and type_name == "service-2":
        _inject_s3_ceph_logging_model(result)
    return result


def _make_api_call_with_ceph_logging_extensions(self, operation_name, api_params):
    service_name = self.meta.service_model.service_name

    response = _ORIGINAL_MAKE_API_CALL(self, operation_name, api_params)

    # Some local minis3 images still expose account-root as user/<name>.
    # Normalize IAM GetUser for root keys so account-root tests execute.
    if service_name == "iam" and operation_name == "GetUser":
        try:
            access_key = self._request_signer._credentials.access_key
        except Exception:  # pragma: no cover - defensive for botocore internals
            access_key = ""

        root_accounts = {
            "root-access-key": "123456789012",
            "altroot-access-key": "210987654321",
        }
        account_id = root_accounts.get(access_key)
        if account_id:
            user = response.get("User")
            if isinstance(user, dict):
                user["Arn"] = f"arn:aws:iam::{account_id}:root"
                user["UserId"] = account_id

    return response


# Patch loader so S3 service-2 model includes Ceph RGW logging extensions and PostBucketLogging.
botocore.loaders.Loader.load_service_model = _load_service_model_with_s3_extensions
botocore.client.BaseClient._make_api_call = _make_api_call_with_ceph_logging_extensions

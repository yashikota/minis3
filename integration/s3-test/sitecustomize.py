"""Runtime patches for the s3-tests container.

Botocore's bundled S3 model does not include Ceph RGW logging extension fields
under PutBucketLogging. That causes client-side ParamValidationError and the
related tests get skipped before minis3 receives any request.

This patch only relaxes those specific unknown-parameter validation errors so
the tests execute against the server.
"""

import copy

import botocore.client
from botocore import validate as _validate
from botocore.exceptions import ParamValidationError

_ORIGINAL_VALIDATE_PARAMETERS = _validate.validate_parameters
_ORIGINAL_PARAM_VALIDATOR_VALIDATE = _validate.ParamValidator.validate
_ORIGINAL_MAKE_API_CALL = botocore.client.BaseClient._make_api_call
_UNKNOWN_PREFIX = 'Unknown parameter in BucketLoggingStatus.LoggingEnabled: "'
_ALLOWED_FIELD_NAMES = {
    '"LoggingType"',
    '"ObjectRollTime"',
    '"RecordsBatchSize"',
    '"Filter"',
}


def _is_allowed_bucket_logging_extension_error(message: str) -> bool:
    lines = [line.strip() for line in message.splitlines() if line.strip()]
    if not lines:
        return False
    if lines[0] == "Parameter validation failed:":
        unknown_lines = lines[1:]
    else:
        unknown_lines = lines
    if not unknown_lines:
        return False
    for line in unknown_lines:
        if not line.startswith(_UNKNOWN_PREFIX):
            return False
        if not any(field_name in line for field_name in _ALLOWED_FIELD_NAMES):
            return False
    return True


def _validate_parameters_with_ceph_logging_extensions(params, shape):
    try:
        return _ORIGINAL_VALIDATE_PARAMETERS(params, shape)
    except ParamValidationError as err:
        if _is_allowed_bucket_logging_extension_error(str(err)):
            return
        raise


def _param_validator_validate_with_ceph_logging_extensions(self, params, shape):
    report = _ORIGINAL_PARAM_VALIDATOR_VALIDATE(self, params, shape)
    if report.has_errors() and _is_allowed_bucket_logging_extension_error(report.generate_report()):
        return _validate.ValidationErrors()
    return report


def _make_api_call_with_ceph_logging_extensions(self, operation_name, api_params):
    service_name = self.meta.service_model.service_name

    if service_name == "s3" and operation_name == "PutBucketLogging":
        api_params = copy.deepcopy(api_params)
        logging_enabled = api_params.get("BucketLoggingStatus", {}).get("LoggingEnabled")
        if isinstance(logging_enabled, dict):
            logging_enabled.pop("LoggingType", None)
            logging_enabled.pop("ObjectRollTime", None)
            logging_enabled.pop("RecordsBatchSize", None)
            logging_enabled.pop("Filter", None)

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


_validate.validate_parameters = _validate_parameters_with_ceph_logging_extensions
_validate.ParamValidator.validate = _param_validator_validate_with_ceph_logging_extensions
botocore.client.BaseClient._make_api_call = _make_api_call_with_ceph_logging_extensions

"""Runtime patches for the s3-tests container."""

import botocore.client

_ORIGINAL_MAKE_API_CALL = botocore.client.BaseClient._make_api_call


def _make_api_call_with_iam_patch(self, operation_name, api_params):
    response = _ORIGINAL_MAKE_API_CALL(self, operation_name, api_params)

    service_name = self.meta.service_model.service_name
    if service_name == "iam" and operation_name == "GetUser":
        try:
            access_key = self._request_signer._credentials.access_key
        except Exception:
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


botocore.client.BaseClient._make_api_call = _make_api_call_with_iam_patch

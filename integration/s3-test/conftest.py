"""Load runtime patches for the s3-tests container.

The real patch lives in ``sitecustomize.py`` so it is active for any python
entrypoint. Importing it again from pytest is harmless and guarantees the
patch is applied before tests are collected.
"""

import sitecustomize  # noqa: F401

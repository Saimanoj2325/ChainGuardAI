"""ChainGuard AI shared data contract. SINGLE SOURCE OF TRUTH for API schemas.
Edit models.py, then run `python shared/export_openapi.py` to regenerate contracts/openapi.json.
Frontend generates TypeScript types from contracts/openapi.json."""
from .models import *  # noqa

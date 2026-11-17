"""Dataset profiles: one module per schema, one registry to find them.

Adding a dataset means adding a module here and one line in _MODULES. It does
not mean copying the training pipeline, which is what adding NSL-KDD cost the
first time.
"""

from .base import FAITHFUL, Coverage, Profile
from .registry import (
    DEFAULT_PROFILE,
    get_profile,
    infer_profile,
    list_profiles,
    profile_names,
    resolve_bundle_profile,
)

__all__ = [
    "Coverage",
    "DEFAULT_PROFILE",
    "FAITHFUL",
    "Profile",
    "get_profile",
    "infer_profile",
    "list_profiles",
    "profile_names",
    "resolve_bundle_profile",
]

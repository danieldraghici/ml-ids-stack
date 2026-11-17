"""Profile lookup, and the fallback that keeps already-trained bundles working.

Every bundle in models/ was written before the 'profile' field existed, so none
of them records one. Rather than re-train thirty models, infer_profile() reads
the schema back off the bundle: a bundle whose feature_names are exactly the 70
CIC-IDS2017 columns in order is a cicids2017_cfm bundle, whatever its filename
says. The answer is cached in models/.bundle_index.json so the 112 MB Random
Forest files are deserialised once, not once per lookup.
"""

import importlib

#: Registry key -> module under this package. Listed rather than auto-discovered
#: so the set of profiles is something you read, not something you run to find out.
_MODULES = {
    "cicids2017_cfm": ".cicids2017_cfm",
    "cicids2017_nfs": ".cicids2017_nfs",
    "nfv2": ".nfv2",
    "nfv2_clean": ".nfv2_clean",
    "nfv3_window": ".nfv3_window",
    "gotham": ".gotham",
    "nslkdd": ".nslkdd",
}

#: What the CLIs assume when nothing says otherwise. The legacy baseline, because
#: it is the profile every existing bundle and capture in this repository uses.
DEFAULT_PROFILE = "cicids2017_cfm"

_CACHE = {}


def profile_names():
    """Registered profile names, in declaration order."""
    return list(_MODULES)


def get_profile(name):
    """Look up one profile by name."""
    if name in _CACHE:
        return _CACHE[name]

    if name not in _MODULES:
        known = ", ".join(_MODULES)
        raise KeyError(f"Unknown profile {name!r}. Registered: {known}")

    module = importlib.import_module(_MODULES[name], package=__package__)
    profile = module.PROFILE
    if profile.name != name:
        raise AssertionError(
            f"Profile in {_MODULES[name]} calls itself {profile.name!r}, "
            f"but is registered as {name!r}."
        )
    _CACHE[name] = profile
    return profile


def list_profiles(quiet=False):
    """Every profile that imports cleanly.

    A profile whose module is missing or broken is skipped rather than fatal:
    the Phase 4 schemas land one at a time, and a half-written nfv2 module must
    not stop anyone from using CIC-IDS2017.
    """
    found = []
    for name in _MODULES:
        try:
            found.append(get_profile(name))
        except Exception as exc:          # noqa: BLE001 - report, do not crash
            if not quiet:
                print(f"  (profile {name!r} unavailable: "
                      f"{type(exc).__name__}: {exc})")
    return found


def infer_profile(bundle):
    """Which profile a bundle without a recorded one was trained on.

    Returns a name, or None when no registered schema matches - in which case
    the caller should say so rather than guess, because guessing is exactly the
    failure this whole package exists to remove.
    """
    recorded = bundle.get("profile")
    if recorded:
        return recorded

    for profile in list_profiles(quiet=True):
        if profile.matches_bundle(bundle):
            return profile.name
    return None


def resolve_bundle_profile(bundle):
    """infer_profile(), shaped as the resolver core.bundle expects."""
    return infer_profile(bundle)

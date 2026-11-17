"""Flow extractors: the packet-to-record layer, behind one interface.

Two implementations, chosen for different reasons:

    cicflowmeter - built the CIC-IDS2017 training set, so it reproduces that
                   schema exactly. Live capture through src/extractors/java/
                   LiveCmd.java, which drives the jar's own FlowGenerator.
    nfstream     - the same code offline and live, so any dataset extracted
                   with it has no train/serve skew at all.

Which one a profile can use is declared by the profile, not decided here: see
Profile.extractors and the Coverage it carries.
"""

import importlib

_MODULES = {
    "cicflowmeter": ".cicflowmeter_ext",
    "nfstream": ".nfstream_ext",
}

_CACHE = {}


def extractor_names():
    return list(_MODULES)


def get_extractor(name, **kwargs):
    """Instantiate one extractor by name.

    kwargs reach the constructor, which is how a profile's flow timeouts are
    applied - those are not tuning knobs, they decide what every timing feature
    means, so they travel with the profile rather than defaulting per call.
    """
    if name not in _MODULES:
        known = ", ".join(_MODULES)
        raise KeyError(f"Unknown extractor {name!r}. Registered: {known}")

    module = importlib.import_module(_MODULES[name], package=__package__)
    if kwargs:
        return type(module.EXTRACTOR)(**kwargs)

    if name not in _CACHE:
        _CACHE[name] = module.EXTRACTOR
    return _CACHE[name]


def list_extractors():
    """Every extractor, with whether it can actually run here."""
    found = []
    for name in _MODULES:
        try:
            extractor = get_extractor(name)
            ok, problems = extractor.available()
        except Exception as exc:                              # noqa: BLE001
            found.append((name, None, False, [f"{type(exc).__name__}: {exc}"]))
            continue
        found.append((name, extractor, ok, problems))
    return found


def for_profile(profile, name=None, **kwargs):
    """Pick an extractor the profile declares it can be fed by.

    Refusing an undeclared pairing here is the point: an extractor that
    produces different columns under the same names is the exact failure the
    profile layer exists to make impossible, and it cannot be detected from the
    numbers afterwards.
    """
    if not profile.extractors:
        raise KeyError(
            f"Profile {profile.name!r} has no live extractor - it is an "
            f"offline dataset.\n"
            f"  Nothing can produce its features from packets: they are "
            f"computed over a connection history, not a flow."
        )

    if name is None:
        name = next(iter(profile.extractors))
    elif name not in profile.extractors:
        declared = ", ".join(profile.extractors)
        raise KeyError(
            f"Profile {profile.name!r} cannot be fed by {name!r}.\n"
            f"  Declared extractors: {declared}"
        )

    options = {"flow_timeout": getattr(profile, "flow_timeout", 120.0),
               "activity_timeout": getattr(profile, "activity_timeout", 5.0)}
    options.update(getattr(profile, "extractor_options", {}).get(name, {}))
    options.update(kwargs)
    return get_extractor(name, **options)


#: Columns only one extractor emits. A CSV carries no note of the tool that
#: wrote it, and the profile needs to know - nfstream output has to go through
#: Profile.adapt() and the declared zero-fill, a dataset's own CSV must not.
_SIGNATURES = {
    "nfstream": {"bidirectional_packets", "src2dst_packets", "expiration_id"},
    "cicflowmeter": {"Flow ID", "Flow Duration", "Total Fwd Packet",
                     "Total Fwd Packets"},
}


def detect_extractor(columns):
    """Which extractor produced a frame with these columns, or None.

    None means the file is in some other format - typically the dataset's own
    published CSV, which is aligned as it is.
    """
    present = {str(c).strip() for c in columns}
    for name, signature in _SIGNATURES.items():
        if len(present & signature) >= 2:
            return name
    return None


__all__ = ["extractor_names", "get_extractor", "list_extractors", "for_profile",
           "detect_extractor"]

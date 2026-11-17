"""Feature alignment, cleaning and prediction - the part where correctness lives.

A model trained on CIC-IDS2017 expects 70 specific columns in a specific order.
Feature extractors disagree on naming and ordering, and a positional mismatch
produces confident nonsense without raising anything. Nothing here predicts
unless the columns line up, and when something had to be filled in rather than
measured, it says so.

Two rules this module exists to enforce:

1. A bundle only runs against the schema it was trained on. The profile name
   is checked before the columns are, so a mismatch reports "wrong dataset"
   rather than a wall of missing feature names.
2. Compacted class ids are mapped back before the label encoder sees them.
   predict.py and app.py both skipped this, which silently mislabels every
   temporally split model: cicids2017_temporal reports Bot and DDoS for what
   are really FTP-Patator and SSH-Patator.
"""

import numpy as np
import pandas as pd

# Columns a flow extractor emits that identify a flow rather than describe it.
# Kept as a module-level default because every flow-based profile shares it;
# a profile can widen it through Profile.identifier_columns.
NON_FEATURE_HINTS = {
    "flow id", "src ip", "dst ip", "source ip", "destination ip",
    "src port", "source port", "timestamp", "label", "is_attack",
    "protocol name", "flow_id", "src_ip", "dst_ip", "src_port", "timestamp_str",
}


def canon(name):
    """Normalise a column name for comparison.

    Extractors disagree on 'Flow Duration' vs 'flow_duration' vs 'FlowDuration',
    and the difference is never meaningful.
    """
    return name.lower().replace(" ", "").replace("_", "").replace("/", "")


def align_features(df, feature_names, aliases=None, fillable=None,
                   identifiers=None):
    """Map the input's columns onto the exact training feature set.

    Returns (aligned_dataframe, report). The dataframe is None when alignment
    is impossible - predicting on partially matched columns would silently
    produce garbage, so that case is a hard stop rather than a warning.

    'aliases' is the profile's map from training-time names to the names a
    newer extractor build emits. 'fillable' is the set of features the profile
    has declared its extractor cannot produce; those are zero-filled and listed
    separately in the report, so a reader can tell a measured zero from an
    absent measurement. Anything missing and not fillable still stops the run.
    """
    aliases = aliases or {}
    fillable = set(fillable or ())
    identifiers = identifiers or NON_FEATURE_HINTS

    report = {"exact": [], "renamed": {}, "missing": [], "filled": [],
              "unused": []}

    available = {canon(c): c for c in df.columns}

    mapped = {}
    for wanted in feature_names:
        if wanted in df.columns:
            report["exact"].append(wanted)
            mapped[wanted] = wanted
        elif canon(wanted) in available:
            actual = available[canon(wanted)]
            report["renamed"][wanted] = actual
            mapped[wanted] = actual
        elif wanted in aliases and aliases[wanted] in df.columns:
            actual = aliases[wanted]
            report["renamed"][wanted] = actual
            mapped[wanted] = actual
        elif wanted in aliases and canon(aliases[wanted]) in available:
            actual = available[canon(aliases[wanted])]
            report["renamed"][wanted] = actual
            mapped[wanted] = actual
        elif wanted in fillable:
            report["filled"].append(wanted)
        else:
            report["missing"].append(wanted)

    used = set(mapped.values())
    report["unused"] = [
        c for c in df.columns
        if c not in used and c.lower() not in identifiers
    ]

    if report["missing"]:
        return None, report

    # Reindex into the exact training order - this is what prevents the
    # silent positional misalignment described at the top of this file.
    aligned = pd.DataFrame(index=df.index)
    for name in feature_names:
        if name in mapped:
            aligned[name] = df[mapped[name]].values
        else:
            aligned[name] = 0.0
    return aligned, report


def check_profile(bundle, profile_name, inferred=None):
    """Refuse a bundle that was trained on a different schema.

    Returns an error string, or None when the pairing is fine.

    'inferred' is what the registry worked out from the bundle's column order,
    and it is what makes this check useful at all: every bundle on disk predates
    the profile field, so relying on the recorded value alone would let all of
    them through. With it, pointing an NSL-KDD model at a flow CSV is reported
    as the wrong dataset rather than as 122 missing column names.
    """
    trained_on = bundle.get("profile") or inferred
    if trained_on is None or profile_name is None or trained_on == profile_name:
        return None

    how = "was trained on" if bundle.get("profile") else "has the column order of"
    return (
        f"This bundle {how} profile {trained_on!r}, but the input was read as "
        f"{profile_name!r}.\n"
        f"  The two are different datasets, not different spellings of the same "
        f"one -\n"
        f"  no renaming makes one schema into the other.\n"
        f"  Pass --profile {trained_on} to read the input that way, or choose a "
        f"{profile_name} bundle."
    )


def print_alignment(report, n_expected):
    """Show how well the input matches what the model expects."""
    print("FEATURE ALIGNMENT")
    print("-" * 70)
    print(f"  expected by model : {n_expected}")
    print(f"  matched exactly   : {len(report['exact'])}")
    print(f"  matched by name   : {len(report['renamed'])}")
    if report["filled"]:
        print(f"  ZERO-FILLED       : {len(report['filled'])}")
    print(f"  MISSING           : {len(report['missing'])}")
    print(f"  unused in input   : {len(report['unused'])}")

    if report["renamed"]:
        print("\n  Renamed matches (verify these mean the same thing):")
        for wanted, actual in list(report["renamed"].items())[:10]:
            print(f"    {wanted:<32} <- {actual}")
        if len(report["renamed"]) > 10:
            print(f"    ... and {len(report['renamed']) - 10} more")

    if report["filled"]:
        print("\n  ZERO-FILLED - this extractor cannot measure these:")
        for name in report["filled"][:20]:
            print(f"    {name}")
        if len(report["filled"]) > 20:
            print(f"    ... and {len(report['filled']) - 20} more")
        print("\n  The model was trained on real values for these columns and")
        print("  is now seeing constant zeros. That is a train/serve skew, not")
        print("  a neutral default - treat every number below as an estimate")
        print("  with that caveat attached.")

    if report["missing"]:
        print("\n  MISSING - cannot predict without these:")
        for name in report["missing"][:20]:
            print(f"    {name}")
        if len(report["missing"]) > 20:
            print(f"    ... and {len(report['missing']) - 20} more")
        print("\n  The feature extractor does not produce the same columns as")
        print("  the one used to build the training set. Check that the input")
        print("  really belongs to this profile, and validate a new extractor")
        print("  by re-extracting a capture whose CSV you already have - the")
        print("  columns should match before you trust new data.")

    if report["unused"]:
        print(f"\n  Present in input but unused by the model "
              f"({len(report['unused'])}):")
        print(f"    {', '.join(report['unused'][:8])}"
              + (" ..." if len(report["unused"]) > 8 else ""))
    print("-" * 70 + "\n")


def clean_features(X, quiet=False):
    """Apply the same numeric cleaning the training data received."""
    non_numeric = X.select_dtypes(exclude=[np.number]).columns.tolist()
    if non_numeric:
        if not quiet:
            print(f"Coercing {len(non_numeric)} non-numeric column(s) to numbers: "
                  f"{non_numeric[:5]}")
        for col in non_numeric:
            X[col] = pd.to_numeric(X[col], errors="coerce")

    X = X.replace([np.inf, -np.inf], np.nan)
    n_bad = int(X.isna().any(axis=1).sum())
    if n_bad and not quiet:
        # Training dropped these rows; here they are filled, because dropping
        # flows would silently change the denominator of the false-positive
        # rate this pipeline exists to measure.
        print(f"Filling {n_bad:,} row(s) containing NaN/inf with 0\n")
    return X.fillna(0)


def decode_labels(bundle, encoded):
    """Turn model output into dataset-wide label names.

    This is the class_index fix. train.py warns in save_bundle() that consumers
    must map compacted ids back before calling the label encoder, and neither
    predict.py nor app.py did. For cicids2017_temporal - fitted on 3 of 15
    classes, class_index [0, 7, 11] - the model emits 0/1/2, which the encoder
    read as BENIGN/Bot/DDoS when the truth is BENIGN/FTP-Patator/SSH-Patator.
    """
    class_index = bundle.get("class_index")
    if class_index is not None:
        encoded = np.asarray(class_index)[encoded]
    return bundle["label_encoder"].inverse_transform(encoded)


def predict_frame(bundle, X):
    """Scale, predict and decode. Returns (labels, confidence, probabilities).

    The scaler travels inside the bundle, already fitted on the training data.
    Transform only - fitting here would use this capture's own statistics and
    feed the model something different from what it learned on.
    """
    values = X
    if bundle["scaler"] is not None:
        values = bundle["scaler"].transform(X)

    encoded = bundle["model"].predict(values)
    labels = decode_labels(bundle, encoded)

    probabilities = None
    confidence = None
    if hasattr(bundle["model"], "predict_proba"):
        probabilities = bundle["model"].predict_proba(values)
        confidence = probabilities.max(axis=1)

    return labels, confidence, probabilities

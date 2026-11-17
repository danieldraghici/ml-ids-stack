"""Reading and writing model bundles.

A bundle is one joblib dict holding everything inference needs: the estimator,
the fitted scaler, the label encoder, the exact training column order, and the
metadata that says how it was produced. Saving the estimator alone is a
silent-failure trap - a freshly fitted scaler would use the serving data's own
statistics, and reordered columns would misalign positionally without raising
anything.

This version adds one field: 'profile'. Without it, nothing records which
dataset schema a bundle speaks, and the only defence against feeding an NSL-KDD
model a CICFlowMeter CSV is that the column names happen not to match. That is
an accident, not a check - and newest_bundle() walked straight into it, because
the most recently written bundle on disk is an NSL-KDD one.
"""

import glob
import json
import os
import shutil

import joblib

from .paths import METRICS_DIR, MODELS_DIR, MODEL_VERSIONS_DIR, relative

# Cheap sidecar so newest_bundle() can filter by profile without deserialising
# every candidate - the Random Forest bundles are 112 MB each and there are
# three of them.
INDEX_PATH = os.path.join(MODELS_DIR, ".bundle_index.json")


def list_bundles(models_dir=MODELS_DIR):
    """Every saved *_latest bundle, most recently written first."""
    paths = glob.glob(os.path.join(models_dir, "*_latest.joblib"))
    return sorted(paths, key=os.path.getmtime, reverse=True)


def load_bundle(path):
    """Load a bundle and normalise the keys added over time.

    Bundles written before a field existed simply lack it. Reading them through
    .get() here means every consumer can assume the full shape, instead of each
    one rediscovering that 'class_index' is missing on anything trained before
    the temporal split landed.
    """
    bundle = joblib.load(path)
    bundle.setdefault("class_index", None)
    bundle.setdefault("profile", None)
    bundle.setdefault("categorical_columns", None)
    return bundle


def _index_key(path):
    stat = os.stat(path)
    return f"{int(stat.st_mtime)}:{stat.st_size}"


def _read_index():
    try:
        with open(INDEX_PATH, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def _write_index(index):
    try:
        os.makedirs(MODELS_DIR, exist_ok=True)
        with open(INDEX_PATH, "w", encoding="utf-8") as fh:
            json.dump(index, fh, indent=2, sort_keys=True)
    except OSError:
        pass        # the index is a cache; failing to write it is not fatal


def describe_bundle(path, resolver=None):
    """Profile name, feature count and class count, without a full load if cached.

    'resolver' is passed in by the caller rather than imported, because core
    must not depend on the profile registry. It takes a loaded bundle and
    returns a profile name - which is how bundles written before the 'profile'
    field existed still get classified, by matching their feature_names against
    the registered schemas.
    """
    index = _read_index()
    key = _index_key(path)
    cached = index.get(os.path.basename(path))
    if cached and cached.get("key") == key:
        return cached

    bundle = load_bundle(path)
    profile = bundle.get("profile")
    if profile is None and resolver is not None:
        profile = resolver(bundle)

    entry = {
        "key": key,
        "profile": profile,
        "n_features": len(bundle["feature_names"]),
        "n_classes": len(bundle["label_encoder"].classes_),
        "model": bundle["metadata"].get("model"),
        "target": bundle["metadata"].get("target"),
    }
    index[os.path.basename(path)] = entry
    _write_index(index)
    return entry


def newest_bundle(profile=None, models_dir=MODELS_DIR, resolver=None):
    """The most recently written bundle, optionally restricted to one profile.

    The profile filter is the whole point. Unfiltered, this returns whatever
    was trained last - which on this repository is an NSL-KDD model whose 122
    one-hot columns cannot align with a 70-column flow CSV. The failure used to
    surface as a wall of MISSING feature names; now it either picks a model
    that speaks the right schema, or says plainly that none does.
    """
    paths = list_bundles(models_dir)
    if not paths:
        raise FileNotFoundError(
            f"No bundle in {relative(models_dir)}. Train a model first."
        )

    if profile is None:
        return paths[0]

    for path in paths:
        if describe_bundle(path, resolver).get("profile") == profile:
            return path

    raise FileNotFoundError(
        f"No bundle for profile {profile!r} in {relative(models_dir)}.\n"
        f"  {len(paths)} bundle(s) present, none of them trained on this "
        f"schema.\n  Train one with: python src/train.py --profile {profile}"
    )


def save_bundle(model, scaler, label_encoder, feature_names, metadata,
                model_name, output_name, no_save, class_index=None,
                profile=None, extra=None):
    """Save the model together with everything inference needs.

    'class_index' is None for any run whose training set covered every class,
    which is every random-split run - such a bundle behaves exactly as before
    and label_encoder.inverse_transform(model.predict(X)) is correct. It is a
    list only when a temporal split left classes out of the training set: the
    model then emits compacted ids, and a consumer must map them back with
    class_index[prediction] before touching the label encoder.

    'extra' carries whatever a profile needs beyond the common shape - NSL-KDD
    puts 'categorical_columns' there, because its encoded feature_names are
    meaningless without knowing which columns were one-hot expanded.
    """
    if no_save:
        print("--no-save set, bundle not written.\n")
        return None

    os.makedirs(MODEL_VERSIONS_DIR, exist_ok=True)

    bundle = {
        "model": model,
        "scaler": scaler,                    # None when unscaled (trees don't need it)
        "label_encoder": label_encoder,
        "feature_names": feature_names,      # exact column order used for training
        # None unless the training set was missing classes - see the docstring
        "class_index": None if class_index is None else [int(c) for c in class_index],
        "profile": profile,                  # which dataset schema this speaks
        "metadata": metadata,
    }
    if extra:
        bundle.update(extra)

    if class_index is not None:
        print(f"NOTE: this model was fitted on {len(class_index)} of "
              f"{len(label_encoder.classes_)} classes, so it emits compacted "
              "class ids.")
        print("      Consumers must map them with bundle['class_index'] before "
              "calling")
        print("      label_encoder.inverse_transform(), or the labels will be "
              "wrong.")

    stem = f"{output_name}_{model_name}"
    timestamp = metadata["timestamp"].replace(":", "").replace("-", "")[:15]
    version_path = os.path.join(MODEL_VERSIONS_DIR, f"{stem}_{timestamp}.joblib")
    latest_path = os.path.join(MODELS_DIR, f"{stem}_latest.joblib")

    joblib.dump(bundle, version_path)
    if os.path.exists(latest_path):
        os.remove(latest_path)
    shutil.copy2(version_path, latest_path)

    # Refresh the sidecar so the new bundle is filterable straight away.
    index = _read_index()
    index[os.path.basename(latest_path)] = {
        "key": _index_key(latest_path),
        "profile": profile,
        "n_features": len(feature_names),
        "n_classes": len(label_encoder.classes_),
        "model": metadata.get("model"),
        "target": metadata.get("target"),
    }
    _write_index(index)

    size_mb = os.path.getsize(version_path) / 1024 ** 2
    print(f"Saved -> {relative(version_path)}  ({size_mb:.1f} MB)")
    print(f"Updated -> {relative(latest_path)}")
    return version_path


def save_metrics(metrics, metadata, model_name, output_name, no_save):
    """Write metrics as JSON so plots and thesis tables can be regenerated."""
    if no_save:
        return None

    os.makedirs(METRICS_DIR, exist_ok=True)
    stem = f"{output_name}_{model_name}"
    timestamp = metadata["timestamp"].replace(":", "").replace("-", "")[:15]
    path = os.path.join(METRICS_DIR, f"{stem}_{timestamp}.json")

    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"metadata": metadata, "metrics": metrics}, fh, indent=2)

    print(f"Metrics -> {relative(path)}\n")
    return path

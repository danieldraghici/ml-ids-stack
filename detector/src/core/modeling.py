"""Estimator construction and label-space bookkeeping.

Lifted verbatim from train.py and nslkdd.py, which carried byte-identical
copies of compact_label_space() and detect_gpu() and near-identical copies of
make_model(). Holding the estimator constant across datasets is what makes a
cross-dataset comparison mean anything, so there must be exactly one definition.
"""

import numpy as np
from sklearn.ensemble import RandomForestClassifier

# Classes below this count are reported but flagged as statistically
# unreliable - results on them should not be presented without caveats.
MIN_RELIABLE_SUPPORT = 50


def compact_label_space(y_train, label_encoder):
    """Renumber the training labels to 0..k-1 when some classes are absent.

    The label encoder is fitted on the whole dataset so that every report names
    all classes. Under a temporal split the training set covers only some of
    them, leaving gaps in the encoded ids (0, 3, 4, 7, ...). XGBoost refuses
    that outright - it requires the training labels to be exactly 0..k-1 - so
    the ids are compacted before the fit and the predictions are mapped back
    afterwards, which keeps every metric in the dataset-wide label space.

    Returns (y_fit, class_index). class_index[i] is the dataset-wide id of the
    model's class i, or None when the training set already covers every class,
    in which case nothing is renumbered and the fit is unchanged.
    """
    present = np.unique(y_train)
    if len(present) == len(label_encoder.classes_):
        return y_train, None

    # searchsorted maps each id to its position in the sorted present ids,
    # which is the compacted id, and preserves the ordering.
    return np.searchsorted(present, y_train), present


def detect_gpu():
    """Check whether XGBoost can actually reach a CUDA device.

    The --gpu flag records intent, not reality: XGBoost silently falls back
    to CPU when no device is visible (a disabled dGPU on battery power does
    this). Recording the requested flag instead of the effective one makes
    saved metadata lie about how a model was trained, which defeats the
    point of storing it for reproducibility.
    """
    try:
        import json as _json

        import xgboost as xgb

        if not xgb.build_info().get("USE_CUDA", False):
            return False, "XGBoost built without CUDA support"

        # A throwaway fit is the only reliable probe: build_info() reports
        # compile-time capability, not whether a device is visible right now.
        # The booster's own config is then authoritative - it reports the
        # device actually used, after any silent fallback. Parsing the
        # fallback warning instead is fragile: XGBoost only emits it once
        # per process, and not on every code path.
        probe = xgb.XGBClassifier(
            n_estimators=1, max_depth=1, device="cuda", verbosity=0
        )
        probe.fit(np.array([[0.0], [1.0]]), np.array([0, 1]))

        config = _json.loads(probe.get_booster().save_config())
        device = config["learner"]["generic_param"]["device"]
        if device.startswith("cuda"):
            return True, f"CUDA device available ({device})"
        return False, "no visible GPU (check drivers / dGPU power settings)"

    except Exception as exc:
        return False, f"probe failed: {type(exc).__name__}"


def make_model(name, n_classes, random_state, n_jobs, gpu,
               n_estimators, max_depth, learning_rate, class_weight=None):
    """Instantiate the requested estimator.

    Both are tree ensembles, chosen because gradient boosting and random
    forests consistently outperform deep learning on tabular flow features
    while keeping inference in the millisecond range - which matters for a
    system meant to run on live traffic.

    class_weight is Random Forest only and defaults to None; the NSL-KDD
    pipeline never passed it, and XGBoost expresses the same idea through
    sample weights instead.
    """
    if name == "rf":
        return RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,          # None = grow until pure
            n_jobs=n_jobs,
            random_state=random_state,
            class_weight=class_weight,
        )

    if name == "xgb":
        from xgboost import XGBClassifier

        params = {
            "n_estimators": n_estimators,
            # XGBoost needs a concrete depth; RF's None means "unlimited"
            "max_depth": max_depth if max_depth is not None else 8,
            "learning_rate": learning_rate,
            "tree_method": "hist",
            "random_state": random_state,
            "n_jobs": n_jobs,
        }
        if gpu:
            params["device"] = "cuda"
        if n_classes > 2:
            params["objective"] = "multi:softprob"
            params["num_class"] = n_classes

        return XGBClassifier(**params)

    raise ValueError(f"Unknown model '{name}'")


class TwoStageDetector:
    """Attack or not at a calibrated threshold, then which family of attack.

    The detector is binary because that is the decision an operator needs and
    the one that can be validated across networks; the family is secondary
    information attached to an alert, from a second model trained on attack
    flows only. Wrapping both behind predict()/predict_proba() keeps every
    consumer (live.py, the dashboard, predict.py) on the one code path all
    bundles use: class 0 is benign, class i > 0 is families[i - 1].

    predict_proba() returns [1 - p, p * P(family | attack) ...], so its row
    maximum - what the consumers show as confidence - is the probability of
    the label actually emitted.
    """

    def __init__(self, detector, threshold, family_model, families):
        self.detector = detector
        self.threshold = float(threshold)
        self.family_model = family_model
        self.families = list(families)
        self.classes_ = np.arange(len(self.families) + 1)

    def attack_probability(self, X):
        return self.detector.predict_proba(X)[:, 1]

    def _family_proba(self, X):
        if self.family_model is None:
            return np.ones((len(X), 1))
        return self.family_model.predict_proba(X)

    def predict_proba(self, X):
        p = self.attack_probability(X)
        return np.column_stack([1.0 - p, p[:, None] * self._family_proba(X)])

    def predict(self, X):
        p = self.attack_probability(X)
        out = np.zeros(len(p), dtype=int)
        hit = p >= self.threshold
        if hit.any():
            rows = X[hit]
            out[hit] = 1 + np.asarray(self._family_proba(rows)).argmax(axis=1)
        return out

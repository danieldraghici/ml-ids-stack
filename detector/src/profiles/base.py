"""The Profile contract: everything that changes when the dataset changes.

The observation this package is built on is that flow generation depends on the
dataset. CIC-IDS2017 has 70 CICFlowMeter columns; NF-UQ-NIDS-v2 has 43 NetFlow
v9 fields produced by nProbe; NSL-KDD has 41 connection records with three
categorical columns; Gotham ships raw packets and leaves the choice open.
Swapping the dataset is therefore not a data decision, it is a schema decision
that reaches all the way down to which packet-capture tool can feed the model.

Before this existed, the only way to add a dataset was to copy the pipeline:
nslkdd.py is 949 lines, most of them identical to train.py. A profile is the
seam that stops the third dataset from becoming a third copy.

A profile declares:
  - the schema (column names, order, which are identifiers, which is the label)
  - how to load and encode its raw form
  - which extractors can produce that schema, and with what fidelity

That last part is the one that is easy to skip and expensive to skip. See
Coverage below.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Coverage:
    """What an extractor can actually produce for one profile's schema.

    A model trained on nProbe's 43 NetFlow fields and served with nfstream is
    not running on the features it learned: nfstream measures about 24 of them
    directly, can compute another 10 through a plugin, and cannot produce the
    retransmission counters or the DNS/FTP fields at all. Those last ones
    become constant zeros.

    Zero-filling is a defensible choice - dropping the flows instead would
    quietly shrink the denominator of every rate the system reports, which is
    the same reasoning that makes clean_features() fill rather than drop. What
    is not defensible is doing it silently. This class is how a profile states
    the gap up front, so align_features() can fill those columns deliberately
    and print what it filled, instead of hard-stopping on nine missing names
    or, worse, appearing to work.

    native      - measured directly by the extractor
    derived     - computed from other measurements; the value is a short note
                  saying how, because "derived" spans honest arithmetic and
                  rough proxies and the reader needs to know which
    unavailable  - not obtainable; zero-filled, and reported as such
    """

    native: frozenset = frozenset()
    derived: dict = field(default_factory=dict)
    unavailable: frozenset = frozenset()

    @property
    def fillable(self):
        """Features align_features() may zero-fill for this pairing."""
        return self.unavailable

    def summary(self, total):
        parts = [f"{len(self.native)} native"]
        if self.derived:
            parts.append(f"{len(self.derived)} derived")
        if self.unavailable:
            parts.append(f"{len(self.unavailable)} zero-filled")
        return f"{'/'.join(parts)} of {total}"

    def is_faithful(self):
        """True when the extractor reproduces the schema without gaps."""
        return not self.unavailable and not self.derived


#: Coverage for the extractor that produced a dataset in the first place.
#: Re-extracting with the same tool that built the training set is the only
#: pairing with no train/serve skew by construction.
FAITHFUL = Coverage()


class Profile:
    """One dataset schema, and everything that depends on it.

    Subclasses override the attributes and the two or three methods that
    genuinely differ. Anything a subclass does not override is either shared
    (and lives in core/) or does not apply to that dataset.
    """

    #: Registry key, and the value written into every bundle this profile trains.
    name = ""
    #: One line, shown by `--list-profiles`.
    description = ""

    #: Canonical training column order, or None when it is only known after
    #: encoding (NSL-KDD's one-hot width depends on the service values present).
    feature_names = None

    #: Column holding the multiclass label, and the binary attack flag.
    label_column = "Label"
    binary_column = "is_attack"

    #: The label this dataset uses for "no attack". It is spelled differently
    #: by every dataset - BENIGN (CIC-IDS2017), Benign (NF-v2, Gotham), normal
    #: (NSL-KDD) - and code that assumed one spelling treated every benign
    #: flow of the others as an alert. Nothing outside the profile may assume
    #: a spelling; ask is_benign() instead.
    benign_label = "BENIGN"

    #: Stem for bundles and metrics when train.py gets no --output-name. None
    #: means the profile name. Defaulting to a fixed "cicids2017" used to make a
    #: run on any other profile overwrite the CIC-IDS2017 *_latest bundle.
    output_stem = None

    #: Provenance columns: they say where a row came from, not what the traffic
    #: looked like, so they are dropped from X. CIC-IDS2017's 'day' matters most
    #: - it is an integer that survives the numeric filter and perfectly
    #: identifies several attack classes, because each attack ran on one day.
    #: That is not a detector, it is a calendar.
    meta_columns = ()

    #: Columns to one-hot encode before training.
    categorical_columns = ()

    #: Columns that identify a flow rather than describe it. Dropped from X,
    #: carried into alerts so a flagged flow can be traced back to its capture.
    identifier_columns = frozenset()

    #: Training-time name -> name a different extractor build emits.
    aliases = {}

    #: extractor name -> Coverage. An extractor absent from this mapping cannot
    #: feed this profile at all.
    extractors = {}

    #: Flow expiry in seconds: when an open flow is closed and emitted, and how
    #: much silence ends an "active" period. These live on the profile, not on
    #: the call, because they are not tuning knobs - they decide the value of
    #: every duration, IAT, Active and Idle feature. Extracting a training set
    #: at one setting and serving at another reintroduces exactly the
    #: train/serve skew the rest of this design removes, and nothing in the
    #: output would show it. The defaults are CICFlowMeter's, which is what
    #: produced CIC-IDS2017.
    flow_timeout = 120.0
    activity_timeout = 5.0

    #: Extractor name -> extra constructor options this schema depends on, for
    #: the same reason the timeouts live here. NF-v2 counts bytes at the IP
    #: layer, as NetFlow does; nfstream counts the whole frame unless told
    #: otherwise, which would inflate every byte and packet-size feature by
    #: the Ethernet header.
    extractor_options = {}

    #: Default processed dataset, relative to the repository root.
    default_data = None

    #: Noun for console output: CIC-IDS2017 counts flows, NSL-KDD counts rows.
    unit = "flow"

    # -- loading -------------------------------------------------------

    def load_raw(self, path=None):
        """Load this profile's processed dataset as a dataframe."""
        raise NotImplementedError(f"{self.name}: load_raw")

    def repair(self, df):
        """Undo known damage in a published copy of this dataset.

        Redistributed copies are not always faithful: one NF-UQ-NIDS-v2
        Parquet on Kaggle stores ports in int16, so every port above 32767
        reads as negative. Called by load_raw() and by sample_large.py on each
        chunk, so it must be idempotent. The default does nothing.
        """
        return df

    def build_features(self, df, target):
        """Split a loaded frame into (X, y_raw).

        Both label columns are dropped from X regardless of which one is the
        target, otherwise the unused one leaks the answer straight into the
        model.
        """
        raise NotImplementedError(f"{self.name}: build_features")

    def encode(self, X_train, X_eval):
        """One-hot encode categoricals, fitting on train only.

        Returns (X_train, X_eval, feature_names, report). The report records
        what the alignment dropped or kept as always-zero, which belongs in the
        run metadata - a column set that differs between the two sides is the
        failure this step exists to prevent, so the run should record that it
        did not happen.

        The default is the identity: most flow schemas are numeric throughout.
        """
        return X_train, X_eval, list(X_train.columns), {}

    # -- extractor pairing ---------------------------------------------

    def coverage(self, extractor_name):
        """Coverage for one extractor, or None when it cannot feed this profile."""
        return self.extractors.get(extractor_name)

    def adapt(self, df, extractor_name):
        """Compute this profile's derived columns from an extractor's output.

        Renames are handled by `aliases`, which costs nothing and cannot be got
        wrong. Anything needing arithmetic - a rate from bytes and a duration,
        a TCP flag bitmask from per-flag packet counts - lands here instead,
        where it is written once, next to the Coverage entry that declares it
        derived rather than measured.

        The default is the identity: a profile whose extractor produced its own
        training set has nothing to derive.
        """
        return df

    def fillable_for(self, extractor_name):
        """Features to zero-fill when serving this profile from an extractor."""
        cov = self.coverage(extractor_name)
        return cov.fillable if cov else frozenset()

    def servable_features(self, feature_names, extractor_name):
        """The subset of feature_names an extractor can actually produce.

        Training on this subset is how the zero-fill skew is removed rather
        than just reported: a model that never saw RETRANSMITTED_* cannot be
        misled by them arriving as constant zeros.
        """
        missing = self.fillable_for(extractor_name)
        return [f for f in feature_names if f not in missing]

    # -- labels ----------------------------------------------------------

    def benign_names(self):
        """Every spelling of 'no attack' a model of this profile can emit.

        The binary target encodes benign as 0, which the label encoder turns
        into the string "0"; NSL-KDD's binary target keeps "normal".
        """
        return {str(self.benign_label).casefold(), "0"}

    def is_benign(self, label):
        return str(label).strip().casefold() in self.benign_names()

    def expect_label(self, expect, classes=None):
        """Translate a user's --expect into this profile's own spelling.

        "BENIGN" means benign on every profile, so an operator does not have to
        know how each dataset writes it. Any other value is matched
        case-insensitively against the model's classes, and returned unchanged
        when nothing matches - the report then shows 0 matches, which is the
        correct answer for a label the model cannot emit.
        """
        if expect is None:
            return None
        # list(): the classes are usually a label encoder's numpy array, whose
        # truth value is an error rather than False when it is non-empty.
        classes = [] if classes is None else list(classes)
        if str(expect).strip().casefold() in {"benign", "normal", "0"}:
            # A binary model emits "0", not the dataset's benign name.
            for name in classes:
                if self.is_benign(name):
                    return name
            return self.benign_label
        for name in classes:
            if str(name).casefold() == str(expect).casefold():
                return name
        return expect

    def default_output_name(self):
        return self.output_stem or self.name

    def bundle_extra(self):
        """Extra keys this profile needs stored in its bundles."""
        return {}

    def zero_filled_for(self, bundle, extractor_name):
        """Which of a bundle's features this extractor would have to zero-fill.

        Per bundle, not per profile: a model trained with
        `train.py --servable-by nfstream` has none, while one trained on the
        full schema has every unavailable feature it kept.
        """
        missing = self.fillable_for(extractor_name)
        return [f for f in bundle.get("feature_names") or () if f in missing]

    def matches_bundle(self, bundle):
        """Whether a bundle with no recorded profile was trained on this schema.

        Every bundle on disk predates the profile field. Matching on the exact
        training column order is what lets them keep working: a bundle with
        these 70 names in this order is a bundle of this profile, whatever the
        filename says.
        """
        if not self.feature_names:
            return False
        return list(bundle.get("feature_names") or ()) == list(self.feature_names)

    def __repr__(self):
        n = len(self.feature_names) if self.feature_names else "?"
        return f"<Profile {self.name} ({n} features)>"

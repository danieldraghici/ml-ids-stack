"""Repository paths, resolved from this file rather than the working directory.

Every entry point used to build paths like os.path.join("models", ...), which
only works when the process happens to start at the repository root. Streamlit
already worked around it with its own PROJECT_ROOT, and the Java extractor
writes its log4j output into whatever directory it was launched from - the
stray logs/ directory in the repository is that bug's fingerprint.

Resolving from __file__ makes every path correct no matter where the process
started, which a background live-capture service needs.
"""

import os

# src/core/paths.py -> src/core -> src -> repository root
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DATA_DIR = os.path.join(PROJECT_ROOT, "data")
RAW_DIR = os.path.join(DATA_DIR, "raw")
PROCESSED_DIR = os.path.join(DATA_DIR, "processed")
CAPTURES_DIR = os.path.join(DATA_DIR, "traffic_captures")

MODELS_DIR = os.path.join(PROJECT_ROOT, "models")
MODEL_VERSIONS_DIR = os.path.join(MODELS_DIR, "versions")

OUTPUTS_DIR = os.path.join(PROJECT_ROOT, "outputs")
METRICS_DIR = os.path.join(OUTPUTS_DIR, "metrics")
FIGURES_DIR = os.path.join(OUTPUTS_DIR, "figures")
TABLES_DIR = os.path.join(OUTPUTS_DIR, "tables")

LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")


def relative(path):
    """Path relative to the repository root, for readable console output."""
    try:
        return os.path.relpath(path, PROJECT_ROOT)
    except ValueError:      # different drive on Windows
        return path

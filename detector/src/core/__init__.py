"""Dataset-independent machinery shared by every training and inference path.

Nothing in here may import a profile or an extractor. The dependency arrow
points one way - profiles and extractors build on core, never the reverse -
which is what stops a dataset-specific assumption from leaking back into the
shared code and quietly changing results for every other dataset.
"""

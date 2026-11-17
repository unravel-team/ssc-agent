"""Sources: one file per source, discovered automatically. See base.py for the classes and intel_api/README.md to add one."""

from .base import FeedSource, PackageSource, SearchSource, Source  # noqa: F401
from .registry import register  # noqa: F401

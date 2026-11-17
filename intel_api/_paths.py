"""Where things live. The sources API is self-contained: it never imports agent code.

Also re-exports L (intel_api/lib/connectors.py: HTTP fetch, source config, per-source functions), imported last so
the paths above exist before the connectors load.
"""

import os

API_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(API_DIR)  # the repo the service sits in (only used for docs output)
CONFIG_DIR = os.path.join(API_DIR, "config")
DATA_DIR = os.path.join(API_DIR, "data")

from .lib import connectors as L  # noqa: E402 - after the paths, which the connectors' importers rely on

__all__ = ["API_DIR", "CONFIG_DIR", "DATA_DIR", "ROOT", "L"]

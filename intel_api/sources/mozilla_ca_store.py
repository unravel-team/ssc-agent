"""Mozilla's trusted root CAs. A root that disappears from the store becomes a ca_distrust signal."""

from .._paths import L
from .base import FeedSource
from .registry import register


@register
class MozillaCaStore(FeedSource):
    key = "mozilla_ca_store"
    order = 50

    def pull(self, state):
        roots = L.mozilla_store()
        prev = state.get("roots") or {}
        if len(roots) < 50 or (prev and len(roots) < 0.8 * len(prev)):
            raise RuntimeError(f"CA store looks incomplete ({len(roots)} roots); keeping the previous copy")
        out = [
            self.signal(
                "ca_distrust",
                f"Removed from Mozilla's trusted roots: {label}",
                key=fp,
                url="https://wiki.mozilla.org/CA/Removed_Certificates",
                subject={"type": "ca", "name": label},
                data={"fingerprint_sha256": fp},
            )
            for fp, label in prev.items()
            if fp not in roots
        ]
        return out, {"roots": roots, "count": len(roots)}

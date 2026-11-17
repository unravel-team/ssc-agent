# The agents container: runs only the agents (headless Claude Code). No database access: it takes jobs from the
# API with an "agent" key and sends the advisories back. Build context: this folder.
ARG PYTHON_IMAGE=python:3.13.18-slim@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1

# ---------------------------------------------------------------- download Claude Code: one pinned release, checksum-verified
FROM ${PYTHON_IMAGE} AS claude
# 2.1.316 (built 2026-10-30). SHA-256 values from its manifest.json; the build fails if the download differs.
ARG CLAUDE_VERSION=2.1.316
ARG CLAUDE_SHA256_X64=fd13c70000fec3f2116dfbcbb6121210b4a29328bf0e46210a59dd594a67d824
ARG CLAUDE_SHA256_ARM64=55cdb8e162d190432696ea54010e0fca2e18d06fa7a7127fd563b9ffd4f22624
ARG TARGETARCH
COPY fetch_claude.py /tmp/fetch_claude.py
RUN python /tmp/fetch_claude.py "$CLAUDE_VERSION" "$TARGETARCH" "$CLAUDE_SHA256_X64" "$CLAUDE_SHA256_ARM64" /claude

# ---------------------------------------------------------------- runtime
FROM ${PYTHON_IMAGE}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/home/agent \
    DISABLE_AUTOUPDATER=1 DISABLE_TELEMETRY=1 DISABLE_ERROR_REPORTING=1 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
RUN useradd --system --uid 10002 --home-dir /home/agent --shell /usr/sbin/nologin agent \
 && mkdir -p /work /home/agent && chown agent:agent /work /home/agent   # compose mounts these as tmpfs; Fly uses them as is
COPY --from=claude /claude /usr/local/bin/claude
COPY runner.py advisor.md /app/
USER agent
WORKDIR /work
CMD ["python", "/app/runner.py"]

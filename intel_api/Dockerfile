# Sources API (intel_api) server image. Build context: this folder.
# docker compose up -d --build

ARG PYTHON_IMAGE=python:3.13.18-slim

# ---------------------------------------------------------------- build: Poetry installs the locked dependencies
FROM ${PYTHON_IMAGE} AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    POETRY_NO_INTERACTION=1 POETRY_VIRTUALENVS_CREATE=false POETRY_CACHE_DIR=/tmp/poetry-cache

COPY poetry-tools.txt /tmp/poetry-tools.txt
RUN python -m venv /opt/poetry \
 && /opt/poetry/bin/pip install --require-hashes --only-binary=:all: --no-deps -r /tmp/poetry-tools.txt

WORKDIR /src
COPY pyproject.toml poetry.lock ./
RUN /opt/poetry/bin/poetry check --lock \
 && python -m venv /venv \
 && VIRTUAL_ENV=/venv PATH=/venv/bin:$PATH /opt/poetry/bin/poetry install --only server --no-root \
 && /venv/bin/python -c "import psycopg; print('psycopg', psycopg.__version__)"

# ---------------------------------------------------------------- runtime
FROM ${PYTHON_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH=/venv/bin:$PATH

RUN apt-get update \
 && apt-get install -y --no-install-recommends wamerican curl bash \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin intel

COPY --from=build /venv /venv

WORKDIR /app
COPY --chown=root:root . /app/intel_api

# Run the startup script as the intel user.
# Replace startup.sh if your script has a different name.
RUN chmod 755 /app/intel_api/scripts/startup.sh

USER intel

EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/v1/health', timeout=4)"]

# Execute startup script, then start the API server.
ENTRYPOINT ["bash", "-c", "bash /app/intel_api/scripts/startup.sh && exec \"$@\"", "--"]

CMD ["python", "-m", "intel_api", "serve", "--host", "0.0.0.0", "--port", "8787"]
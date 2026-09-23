# The image runs the current stable Python; 3.12 and 3.13 are tested in CI (see ci.yml).
# The base is pinned by digest (H-F8): PYTHON_DIGEST defaults to the 3.14 image the
# release was gated on. The CI matrix overrides PYTHON_VERSION and passes an empty
# PYTHON_DIGEST so the tag alone resolves (a digest belongs to exactly one tag).
ARG PYTHON_VERSION=3.14
ARG PYTHON_DIGEST=@sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2
FROM python:${PYTHON_VERSION}-slim${PYTHON_DIGEST}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Dependencies come from the lock (uv, universal, every extra) so a rebuild of
# the same commit installs exactly what the gated build installed — D-045
# found a boto3 patch drift between two builds of one commit before this.
# Regenerate with scripts/lock-deps.sh after editing pyproject.toml. The
# `test` extra stays in the image on purpose: one image serves
# loom/test/consumer/mcp so they can never drift apart (D-011).
COPY requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --no-deps .

# Non-root (H-F8): a fixed uid so k8s fsGroup / compose volumes line up.
# /data is created owned by that user, so a fresh named volume inherits it.
# The entrypoint starts as root only to fix ownership of an older root-owned
# volume, then drops to `loom` via setpriv (util-linux, already in the base).
RUN groupadd -r -g 10001 loom && useradd -r -u 10001 -g loom -d /app loom \
    && mkdir -p /data && chown loom:loom /data /app
COPY deploy/docker-entrypoint.sh /usr/local/bin/loom-entrypoint
RUN chmod 0755 /usr/local/bin/loom-entrypoint
ENTRYPOINT ["loom-entrypoint"]
ENV HOME=/app

ENV LOOM_DB=/data/loom.db
VOLUME /data
EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=4s --start-period=5s --retries=6 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/readyz', timeout=3).status == 200 else 1)"

CMD ["python", "-m", "loom.serve"]

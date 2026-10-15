# The image runs the current stable Python; 3.12 and 3.13 are tested in CI (see ci.yml).
# The base is pinned by digest (H-F8): PYTHON_DIGEST defaults to the 3.14 image the
# release was gated on. The CI matrix overrides PYTHON_VERSION and passes an empty
# PYTHON_DIGEST so the tag alone resolves (a digest belongs to exactly one tag).
ARG PYTHON_VERSION=3.14
ARG PYTHON_DIGEST=@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170
FROM python:${PYTHON_VERSION}-slim${PYTHON_DIGEST}

LABEL org.opencontainers.image.source="https://github.com/seahop/loomctx" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Dependencies come from the lock (uv, universal, every extra) so a rebuild of
# the same commit installs exactly what the gated build installed — D-045
# found a boto3 patch drift between two builds of one commit before this.
# Regenerate with scripts/lock-deps.sh after editing pyproject.toml. The
# `test` extra stays in the image on purpose: one image serves
# loomctx/test/consumer/mcp so they can never drift apart (D-011).
COPY requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN pip install --no-cache-dir --no-deps . \
    # The runtime image needs no package manager: pip (with its vendored
    # msgpack) and the base image's setuptools were the only HIGH findings
    # the Trivy gate reported on the first gated build, and nothing at run
    # time imports either. Removing them is the fix, not pinning them.
    && pip uninstall -y pip setuptools wheel >/dev/null 2>&1 || true \
    && rm -rf /usr/local/lib/python3*/ensurepip /root/.cache

# Non-root (H-F8): a fixed uid so k8s fsGroup / compose volumes line up.
# /data is created owned by that user, so a fresh named volume inherits it.
# The entrypoint starts as root only to fix ownership of an older root-owned
# volume, then drops to `loomctx` via setpriv (util-linux, already in the base).
RUN groupadd -r -g 10001 loomctx && useradd -r -u 10001 -g loomctx -d /app loomctx \
    && mkdir -p /data && chown loomctx:loomctx /data /app
COPY deploy/docker-entrypoint.sh /usr/local/bin/loomctx-entrypoint
RUN chmod 0755 /usr/local/bin/loomctx-entrypoint
ENTRYPOINT ["loomctx-entrypoint"]
ENV HOME=/app

ENV LOOMCTX_DB=/data/loomctx.db
VOLUME /data
EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=4s --start-period=5s --retries=6 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/readyz', timeout=3).status == 200 else 1)"

CMD ["python", "-m", "loomctx.serve"]

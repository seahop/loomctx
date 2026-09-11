# The image runs the current stable Python; 3.12 and 3.13 are tested in CI (see ci.yml).
ARG PYTHON_VERSION=3.14
FROM python:${PYTHON_VERSION}-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir ".[test,scale,postgres,mcp,vector,s3,kafka,connectors]"

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

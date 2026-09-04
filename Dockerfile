FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir ".[test,scale,postgres]"

ENV LOOM_DB=/data/loom.db
VOLUME /data
EXPOSE 8000

CMD ["uvicorn", "loom.api.http:app", "--host", "0.0.0.0", "--port", "8000"]

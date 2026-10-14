FROM python:3.12-slim

WORKDIR /app

# Install PostgreSQL client utilities (pg_dump / pg_restore) for Azure Flexible Server backups
RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql-client \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY db/ ./db/
COPY src/ ./src/
COPY tests/ ./tests/

ENV PYTHONUNBUFFERED=1

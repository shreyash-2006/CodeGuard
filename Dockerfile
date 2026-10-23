# Reproducible image for Render (Docker runtime) or any container host.
#   docker build -t codeguard .
#   docker run -p 8000:8000 -e PORT=8000 codeguard
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install deps first so this layer is cached across code changes.
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# App code + committed model artifact (models/ml.joblib).
COPY . .

EXPOSE 8000
# Render injects $PORT; fall back to 8000 for local runs. Single worker so the
# ML model is loaded exactly once.
CMD ["sh", "-c", "uvicorn codeguard.api:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1"]

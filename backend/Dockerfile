# Sentinel API.
#
# Built with the repository root as context, selected via the
# RAILWAY_DOCKERFILE_PATH=backend/Dockerfile variable on the API service.
# The root holds an npm workspace, so left to autodetection Railway builds
# the Next.js frontend for both services — naming the Dockerfile explicitly
# is what keeps the two apart.

FROM python:3.12-slim

WORKDIR /app

# Dependencies first, so a source-only change reuses the install layer.
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
# Schema and scripts ride along so migrations and the corpus loader can be
# run against production with `railway run python scripts/migrate.py`.
COPY db/ ./db/
COPY scripts/ ./scripts/

# uvicorn is invoked as `app.main:app`, so the import root is backend/.
ENV PYTHONPATH=/app/backend
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

# Shell form so ${PORT} is expanded by Railway at runtime.
CMD uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}

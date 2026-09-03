FROM python:3.11-slim

WORKDIR /app

# Educational lab only — bind localhost in compose / run instructions
ENV DVAPI_HOST=0.0.0.0
ENV DVAPI_PORT=5000
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

COPY backend /app/backend
COPY frontend /app/frontend

RUN addgroup --system heist && \
    adduser --system --ingroup heist --home /nonexistent --no-create-home heist && \
    mkdir -p /data && \
    chown heist:heist /data

WORKDIR /app/backend
EXPOSE 5000
USER heist

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "--timeout", "30", "--limit-request-fields", "50", "--access-logfile", "-", "--error-logfile", "-", "app:app"]

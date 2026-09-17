FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY cloudscan/ ./cloudscan/
COPY web/ ./web/

# Cache dir survives container restarts if you mount a volume at this path.
ENV CLOUDSCAN_CACHE_DIR=/data/cloudscan
RUN mkdir -p /data/cloudscan
VOLUME ["/data/cloudscan"]

EXPOSE 8000

CMD ["uvicorn", "cloudscan.api:app", "--host", "0.0.0.0", "--port", "8000"]

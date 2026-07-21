# NIDS dashboard — Linux image with the full NFStream capture stack.
# Build:  docker build -t nids .
# Run:    docker run --rm -p 8501:8501 nids
# Live capture inside the container needs extra capabilities:
#         docker run --rm -p 8501:8501 --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN nids
FROM python:3.11-slim

WORKDIR /app

# libpcap runtime for NFStream's capture engine
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt scapy nfstream

COPY . .

EXPOSE 8501
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0", "--server.headless=true"]

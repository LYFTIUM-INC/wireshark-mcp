# syntax=docker/dockerfile:1
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && \
    apt-get install -y --no-install-recommends python3 python3-pip python3-venv tshark wget ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

RUN pip3 install --no-cache-dir -r requirements.txt

# Default command expects a mounted PCAP directory at /pcaps and runs integration tests
# Override PCAP_PATH or the command as needed
ENV INTEGRATION=1 \
    PCAP_PATH=/pcaps/http.cap

CMD ["bash","-lc","pytest -q tests/test_integration_tools.py"]
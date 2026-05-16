FROM python:3.11-slim

LABEL maintainer="FMShomit"
LABEL description="Recon99 — Automated Recon & Vulnerability Scanner"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nikto \
    nmap \
    dnsutils \
    curl \
    wget \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.2.4/nuclei_3.2.4_linux_amd64.zip \
    -O /tmp/nuclei.zip && \
    cd /tmp && unzip -q nuclei.zip && \
    mv nuclei /usr/local/bin/ && \
    rm /tmp/nuclei.zip && \
    nuclei -update-templates -silent || true

WORKDIR /app

# Copy and install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Create reports output dir
RUN mkdir -p /app/reports

# Entry point
ENTRYPOINT ["python", "main.py"]
CMD ["--help"]

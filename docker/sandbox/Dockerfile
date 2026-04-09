FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive

# Core apt packages. Use --no-install-recommends for image size.
RUN apt-get update && apt-get install -y --no-install-recommends \
    sqlmap \
    ffuf \
    nikto \
    gobuster \
    wapiti \
    dirb \
    curl \
    wget \
    jq \
    unzip \
    ca-certificates \
    python3 \
    python3-pip \
    python3-venv \
    git \
    && rm -rf /var/lib/apt/lists/*

# Nuclei — download the official binary (arch-aware)
ARG NUCLEI_VERSION=3.3.4
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then NUCLEI_ARCH="amd64"; \
    elif [ "$ARCH" = "arm64" ]; then NUCLEI_ARCH="arm64"; \
    else NUCLEI_ARCH="amd64"; fi && \
    curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${NUCLEI_ARCH}.zip" -o /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip -d /usr/local/bin/ && \
    rm /tmp/nuclei.zip && \
    chmod +x /usr/local/bin/nuclei

# Python-based tools via pip. Use --break-system-packages because debian 13 is PEP 668.
# Each install wrapped so one failure doesn't break the whole layer.
RUN pip3 install --break-system-packages --no-cache-dir httpx aiohttp requests || true
RUN pip3 install --break-system-packages --no-cache-dir arjun || true

# Create the shared workspace directory (will be bind-mounted at runtime)
RUN mkdir -p /workspace
WORKDIR /workspace

# Keep the container running indefinitely
CMD ["sleep", "infinity"]

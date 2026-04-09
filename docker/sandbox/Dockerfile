FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive

# Core apt packages. Use --no-install-recommends for image size.
RUN apt-get update && apt-get install -y --no-install-recommends \
    sqlmap \
    ffuf \
    gobuster \
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
    perl \
    libnet-ssleay-perl \
    && rm -rf /var/lib/apt/lists/*

# Nikto (Perl-based, not in trixie main — clone from GitHub)
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /opt/nikto/program/nikto.pl

# Wapiti (Python-based, install via pip)
RUN pip3 install --break-system-packages --no-cache-dir wapiti3 || true

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

# Pre-download nuclei templates so the first shell_exec nuclei call doesn't
# spend 30-60 seconds on template download during a scan.
RUN nuclei -ut 2>&1 | tail -3 || true

# Kali-convention wordlist symlinks — many scanner recipes assume
# /usr/share/wordlists/dirb/... but Debian's dirb package installs to
# /usr/share/dirb/wordlists/... so we bridge both paths.
RUN mkdir -p /usr/share/wordlists && \
    ln -sf /usr/share/dirb/wordlists /usr/share/wordlists/dirb

# Create the shared workspace directory (will be bind-mounted at runtime)
RUN mkdir -p /workspace
WORKDIR /workspace

# Keep the container running indefinitely
CMD ["sleep", "infinity"]

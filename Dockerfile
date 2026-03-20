FROM python:3.12-slim AS base

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    wget \
    git \
    jq \
    dnsutils \
    whois \
    && rm -rf /var/lib/apt/lists/*

# Install Go for ProjectDiscovery tools
ENV GOPATH=/opt/go
ENV PATH="${GOPATH}/bin:/usr/local/go/bin:${PATH}"
RUN wget -q https://go.dev/dl/go1.23.4.linux-amd64.tar.gz -O /tmp/go.tar.gz \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz

# Install ProjectDiscovery tools
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Install testssl.sh
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl \
    && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh

# Install wafw00f
RUN pip install --no-cache-dir wafw00f

# Install checkdmarc
RUN pip install --no-cache-dir checkdmarc

# Install trufflehog
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Install VXIS
WORKDIR /app
COPY pyproject.toml .
COPY src/ src/
RUN pip install --no-cache-dir -e .

# Create data directories
RUN mkdir -p /app/data /app/reports

ENTRYPOINT ["python", "-m", "vxis.cli.main"]
CMD ["--help"]

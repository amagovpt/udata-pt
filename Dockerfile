FROM python:3.12-slim

# System dependencies for mongoengine, lxml, cryptography, etc.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libxml2-dev \
    libxslt1-dev \
    libffi-dev \
    libssl-dev \
    git \
    curl \
    netcat-openbsd \
    openssl \
    xmlsec1 \
    libxmlsec1-dev \
    libxmlsec1-openssl \
    && rm -rf /var/lib/apt/lists/*

# Install uv for fast dependency management
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:$PATH"

WORKDIR /app

# Trust the /app directory for git (setuptools-scm needs it for versioning)
RUN git config --global --add safe.directory /app

# Copy dependency files first for better layer caching
COPY pyproject.toml uv.lock ./

# Install dependencies
RUN uv sync --no-dev --no-install-project

# Copy application code
COPY . .

# Install the project itself
RUN uv sync --no-dev

# Create directories for logs, uploads, and uwsgi socket
RUN mkdir -p /logs /udata/fs /var/run/uwsgi

# Entrypoint: generates self-signed SAML credentials if not mounted
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Default environment
ENV UDATA_SETTINGS=/app/udata.cfg
ENV PYTHONPATH=/app

EXPOSE 7000

ENTRYPOINT ["/docker-entrypoint.sh"]
# Default command: run the web server via uWSGI
CMD ["uv", "run", "uwsgi", "--ini", "uwsgi/front.ini"]

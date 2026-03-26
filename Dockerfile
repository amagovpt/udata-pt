FROM python:3.12-slim

# System dependencies for mongoengine, lxml, cryptography, etc.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libxml2-dev \
    libxslt1-dev \
    libffi-dev \
    libssl-dev \
    git \
    xmlsec1 \
    libxmlsec1-dev \
    libxmlsec1-openssl \
    && rm -rf /var/lib/apt/lists/*

# Install uv for fast dependency management
RUN pip install --no-cache-dir uv

WORKDIR /app

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

# Default environment
ENV UDATA_SETTINGS=/app/udata.cfg

EXPOSE 7000

# Default command: run the web server via uWSGI
CMD ["uv", "run", "uwsgi", "--ini", "uwsgi/front.ini"]

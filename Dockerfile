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

# Install uv for fast dependency management (system-wide so it is accessible
# to the non-root runtime user)
RUN curl -LsSf https://astral.sh/uv/install.sh \
    | env INSTALLER_NO_MODIFY_PATH=1 UV_INSTALL_DIR=/usr/local/bin sh

# Non-root runtime user. Fixed UID/GID so bind-mounted volumes
# (FS_ROOT, logs, SAML credentials) can be chown'ed predictably on the host.
# Host must have a matching `dadosgov` user with UID/GID 10001.
ARG UDATA_UID=10001
ARG UDATA_GID=10001
RUN groupadd --system --gid ${UDATA_GID} dadosgov \
    && useradd --system --uid ${UDATA_UID} --gid ${UDATA_GID} \
       --no-create-home --home-dir /app --shell /sbin/nologin dadosgov

WORKDIR /app

# Trust the /app directory for git (setuptools-scm needs it for versioning).
# --system makes it visible to both root (at build time) and dadosgov (at runtime).
RUN git config --system --add safe.directory /app

# Copy dependency files first for better layer caching
COPY pyproject.toml uv.lock ./

# Install dependencies
RUN uv sync --no-dev --no-install-project

# Copy application code
COPY . .

# Install the project itself
RUN uv sync --no-dev

# Compile gettext .mo catalogs from the .po sources so Flask-Babel
# can resolve translations at runtime (emails, UI strings).
RUN uv run pybabel compile -D udata -d udata/translations

# Create directories for uploads and uwsgi socket.
# /logs is provided by a bind mount from the host (see docker-compose.yml);
# the host directory is tracked in the repo so it already has the correct
# owner (dadosgov, UID/GID 10001) on clone.
RUN mkdir -p /dadosgov/fs /var/run/uwsgi

# Entrypoint: generates self-signed SAML credentials if not mounted
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Hand ownership of every path the runtime needs to read/write to the
# non-root user (application code + generated .venv, FS_ROOT mount point
# and uwsgi runtime dir). /logs is bind-mounted from the host with the
# correct owner already.
RUN chown -R dadosgov:dadosgov /app /dadosgov /var/run/uwsgi

# Default environment
ENV UDATA_SETTINGS=/app/udata.cfg
ENV PYTHONPATH=/app

EXPOSE 7000

USER dadosgov

ENTRYPOINT ["/docker-entrypoint.sh"]
# Default command: run the web server via uWSGI
CMD ["uv", "run", "uwsgi", "--ini", "uwsgi/front.ini"]

# Image with uv + Python 3.13 preinstalled.
FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim

WORKDIR /app

# Install dependencies first (cached until the lockfile changes).
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Application source.
COPY src ./src

# Use the project virtualenv directly and make src importable, mirroring the
# shadow tests (which put src on PYTHONPATH).
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH="/app/src" \
    PYTHONUNBUFFERED="1"

# Default command; overridden per service in docker-compose.yaml.
CMD ["python", "src/headless.py", "--name", "node", "wait", "999999"]

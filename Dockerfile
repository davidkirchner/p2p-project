# Image with uv + Python 3.13 preinstalled
FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Application source
COPY src ./src

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH="/app/src" \
    PYTHONUNBUFFERED="1"

# Default command (can be overridden per service in docker-compose.yaml)
CMD ["python", "src/headless.py", "--name", "node", "wait", "999999"]

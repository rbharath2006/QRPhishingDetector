FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp \
    XDG_CACHE_HOME=/tmp/.cache \
    XDG_CONFIG_HOME=/tmp/.config

WORKDIR /app

COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt \
    && playwright install --with-deps chromium \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 10001 sandboxuser \
    && mkdir -p /app \
    && chown -R sandboxuser:sandboxuser /app \
    && chmod -R a+rX /ms-playwright

COPY --chown=sandboxuser:sandboxuser app.py ./app.py
USER 10001:10001
EXPOSE 8765
CMD ["python", "/app/app.py"]

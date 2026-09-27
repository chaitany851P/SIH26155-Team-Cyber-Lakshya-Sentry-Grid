# ==============================================================================
# SENTRY-GRID SOVEREIGN DEFENSE CONTAINER
# National Technical Research Organisation (NTRO) • Problem Statement: SIH26155
# Hardened Multi-Stage Build: Native C11 Builder + Hardened Python 3.12 Runtime
# ==============================================================================

# ── STAGE 1: Native C11 Engine Builder ──
FROM gcc:13-bookworm AS native-builder

WORKDIR /src
COPY src_native/ /src/src_native/
COPY Makefile /src/

# Compile native Linux shared library (.so) and native CLI binary with -O3 -mavx2
RUN mkdir -p /src/bin && \
    gcc -O3 -mavx2 -shared -fPIC -o /src/bin/sentry_native.so \
        src_native/sentry_core.c \
        src_native/sentry_crypto.c \
        src_native/sentry_vector.c \
        src_native/sentry_lexer.c \
        src_native/sentry_policy.c && \
    gcc -O3 -mavx2 -o /src/bin/sentry_cli \
        src_native/sentry_core.c \
        src_native/sentry_crypto.c \
        src_native/sentry_vector.c \
        src_native/sentry_lexer.c \
        src_native/sentry_policy.c

# ── STAGE 2: Hardened Python 3.12 Defense Runtime ──
FROM python:3.12-slim-bookworm

LABEL maintainer="NTRO SecOps Directorate" \
      classification="DEFENSE-RESTRICTED" \
      project="SIH26155-SENTRY-GRID"

# Set non-interactive environment
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8090

# Security: Create non-root system user and group (UID 65532)
RUN groupadd -g 65532 nonroot && \
    useradd -u 65532 -g nonroot -s /bin/false -m -d /home/nonroot nonroot

WORKDIR /app

# Install dependencies in a single layer
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source, templates, dataset, samples, and schema
COPY backend/ /app/backend/
COPY templates/ /app/templates/
COPY data/ /app/data/
COPY samples/ /app/samples/
COPY canonical_schema.json /app/canonical_schema.json

# Copy compiled C11 native shared library and CLI from Stage 1
COPY --from=native-builder /src/bin/ /app/bin/

# Enforce secure ownership and permissions
RUN chown -R nonroot:nonroot /app /home/nonroot && \
    chmod 755 /app/bin/sentry_native.so /app/bin/sentry_cli

# Run as non-root user (Principle of Least Privilege)
USER nonroot:nonroot

# Expose sovereign audit port
EXPOSE 8090

# Container Healthcheck (Verifies sub-millisecond /health endpoint)
HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8090/health')" || exit 1

# Launch production ASGI server
ENTRYPOINT ["python", "-m", "uvicorn", "backend.server:app", "--host", "0.0.0.0", "--port", "8090"]

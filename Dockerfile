# CyberIntelGraph API image - deploys to Fly.io (Milestone 18)
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HF_HOME=/app/.hf \
    PORT=8080

WORKDIR /app

# ca-certificates: TLS to Neo4j Aura, MongoDB Atlas and the Groq API
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# CPU-only torch keeps the image small. Set to 0 in fly.toml if the API never embeds text itself.
ARG USE_TORCH_CPU=1
RUN if [ "$USE_TORCH_CPU" = "1" ]; then \
      pip install torch --index-url https://download.pytorch.org/whl/cpu ; \
    fi

# requirements-api.txt is produced by: python scripts/make_requirements_api.py <folders the API imports>
COPY requirements-api.txt .
RUN pip install -r requirements-api.txt

COPY . .

# Optional: bake the embedding model into the image so cold starts do not download it.
# Set to the value of EMBEDDING_MODEL in your .env (for example BAAI/bge-m3). Empty = download at first use.
ARG PREFETCH_MODEL=""
RUN if [ -n "$PREFETCH_MODEL" ]; then \
      python -c "from sentence_transformers import SentenceTransformer as S; S('$PREFETCH_MODEL')" ; \
    fi

# FastAPI app as "package.module:variable". Your roadmap runs: python -m uvicorn backend.main:app
ARG APP_MODULE=backend.main:app
ENV APP_MODULE=${APP_MODULE}

EXPOSE 8080
CMD ["sh", "-c", "uvicorn ${APP_MODULE} --host 0.0.0.0 --port ${PORT} --proxy-headers --forwarded-allow-ips='*'"]

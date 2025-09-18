ARG IMAGE_REPO=debian
ARG IMAGE_TAG=trixie-slim
FROM ${IMAGE_REPO}:${IMAGE_TAG} AS builder

RUN apt-get update && \
    apt-get install -y python3 python3-pip python3-venv && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /usr/src/app/wheels -r requirements.txt

# --- Final Image ---
FROM ${IMAGE_REPO}:${IMAGE_TAG}

RUN groupadd --system --gid 1001 appgroup && \
    useradd --system --uid 1001 --gid appgroup --no-create-home appuser

RUN apt-get update && \
    apt-get install -y python3 python3-pip && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

COPY --from=builder /usr/src/app/wheels /wheels
RUN pip install --break-system-packages --no-cache --ignore-installed packaging /wheels/*

COPY ./app ./app
COPY ./wsgi.py .
COPY --chmod=0755 ./import_pki.sh .
RUN mkdir /pki && chown appuser:appgroup /pki
RUN chown -R appuser:appgroup /usr/src/app

USER appuser

EXPOSE 8500

ENV PYTHONPATH="/usr/src/app"
ENV GUNICORN_LOG_LEVEL="info"
ENV GUNICORN_CMD_ARGS="--bind=0.0.0.0:8500 --workers=2 --access-logfile - --error-logfile - --logger-class app.gunicorn_logging.CustomGunicornLogger"
ENV ENVIRONMENT="production"
ENV FLASK_APP="wsgi:app"

CMD [ "bash", "-c", "gunicorn --log-level $GUNICORN_LOG_LEVEL $FLASK_APP $GUNICORN_CMD_ARGS" ]
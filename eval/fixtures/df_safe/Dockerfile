# syntax=docker/dockerfile:1
FROM python:3.12-slim AS build
WORKDIR /app
COPY requirements.txt .
RUN --mount=type=secret,id=pip_token pip install --no-cache-dir -r requirements.txt
FROM python:3.12-slim
ARG APP_VERSION=1.0.0
ENV LOG_LEVEL=info
COPY --from=build /usr/local/lib/python3.12 /usr/local/lib/python3.12
COPY app/ /app/
RUN useradd --uid 10001 app
USER app
CMD ["python", "/app/main.py"]

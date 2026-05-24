FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    docker.io \
    docker-cli \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG DOCKER_COMPOSE_VERSION=v2.27.0
RUN mkdir -p /root/.docker/cli-plugins && \
    curl -SL "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /root/.docker/cli-plugins/docker-compose && \
    chmod +x /root/.docker/cli-plugins/docker-compose

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

EXPOSE 3000

CMD ["python", "-m", "app.main"]

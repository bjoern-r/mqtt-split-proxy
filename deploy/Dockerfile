# Build from the project root:
#   docker build -f deploy/Dockerfile -t mqtt-split-proxy .
# Run (host networking so 127.0.0.1 reaches the local Mosquitto):
#   docker run -d --name mqtt-split-proxy --network host --restart unless-stopped \
#     -v /etc/mqtt-split-proxy:/config:ro mqtt-split-proxy
FROM python:3.13-slim

WORKDIR /app
COPY pyproject.toml ./
COPY mqtt_split_proxy ./mqtt_split_proxy
RUN pip install --no-cache-dir . && useradd -r -u 10001 mqttproxy

USER mqttproxy
EXPOSE 8883
CMD ["python", "-m", "mqtt_split_proxy", "-c", "/config/config.yaml"]

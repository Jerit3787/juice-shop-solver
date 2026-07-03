FROM python:3.12-slim

WORKDIR /usr/src/app

COPY requirements.txt ./
# core solver deps only; the --browser (Selenium) path needs a Chrome image instead
RUN pip install --no-cache-dir requests pyotp pyzmq hashids "python-socketio[client]"

COPY . .

ENTRYPOINT [ "python", "./solve.py" ]
# Override the target with e.g.:
#   docker run --rm juice-shop-solver --host host.docker.internal --port 3000
CMD ["--host", "host.docker.internal", "--port", "3000"]

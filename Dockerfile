FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    STATE_DIR=/state \
    OUTPUT_DIR=/output

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ix500netscan ./ix500netscan

ARG UID=1000
ARG GID=1000
RUN groupadd -g ${GID} scan && useradd -u ${UID} -g ${GID} -M -s /usr/sbin/nologin scan \
    && mkdir -p /state /output && chown scan:scan /state /output
USER scan
VOLUME ["/state"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/health' % os.environ.get('API_PORT','8099'), timeout=4)" || exit 1

ENTRYPOINT ["python", "-m", "ix500netscan"]
CMD ["run"]

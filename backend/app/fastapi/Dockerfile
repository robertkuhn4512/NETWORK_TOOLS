FROM python:3.14-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && apt-get install -y curl \
 && apt-get install -y iputils-ping \
 && apt-get install -y fping \
 && apt-get install -y jq \
 && rm -rf /var/lib/apt/lists/*

# Add internal CA to system trust store
COPY /certs/networktools_ca.crt /usr/local/share/ca-certificates/networktools_ca.crt
RUN update-ca-certificates

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN python -m pip install --no-cache-dir -U pip

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app

EXPOSE 8000

ARG ARCH=
FROM ${ARCH}python:3.8-alpine

# Install required python packages 
COPY requirements.txt /app/requirements.txt
RUN apk add --no-cache --virtual .build-deps \
        gcc \
        musl-dev && \
    pip install -r /app/requirements.txt && \
    apk del --purge .build-deps

# Copy Grott files here
COPY static /app/static
COPY grott.py /app/grott.py
COPY grottconf.py /app/grottconf.py
COPY grottdata.py /app/grottdata.py
COPY grotthelpers.py /app/grotthelpers.py
COPY grottproxy.py /app/grottproxy.py
COPY grottserver.py /app/grottserver.py
COPY grottsniffer.py /app/grottsniffer.py
COPY examples/grott.ini /app/grott.ini

WORKDIR /app
CMD ["python", "grott.py", "-v"]

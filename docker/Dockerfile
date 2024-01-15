FROM python:3.8-slim

# Install required python packages 
COPY requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt

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

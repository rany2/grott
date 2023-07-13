FROM python:3.8-slim

ENV LANG en_US.UTF-8
ENV LC_ALL en_US.UTF-8

# Run updates
RUN apt-get clean && apt-get update && apt-get upgrade -y

# Set the locale
RUN apt-get install -y locales && locale-gen en_US.UTF-8

#Install required python packages 
COPY requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt

COPY grott.py /app/grott.py
COPY grottconf.py /app/grottconf.py
COPY grottdata.py /app/grottdata.py
COPY grottproxy.py /app/grottproxy.py
COPY grottserver.py /app/grottserver.py
COPY grottsniffer.py /app/grottsniffer.py
COPY grott.ini /app/grott.ini

WORKDIR /app
CMD ["python", "-u", "grott.py", "-v"]

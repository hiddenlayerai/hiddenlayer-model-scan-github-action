FROM python:3.13-slim@sha256:8f3aba466a471c0ab903dbd7cb979abd4bda370b04789d25440cc90372b50e04

RUN apt-get -y update \
	&& apt-get install -y git \
	&& rm -rf /var/lib/apt/lists/*

COPY requirements.txt *.py /

RUN python3 -m pip install --no-cache-dir -r /requirements.txt

ENTRYPOINT ["python3", "/model_scan.py"]

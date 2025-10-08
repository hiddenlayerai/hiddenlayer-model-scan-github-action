FROM python:3.14-slim@sha256:9dc4ef3e628432af2237d1418908f5c6d4528e9f776aaa6e7c95c18854c86e48

RUN apt-get -y update \
	&& apt-get install -y git \
	&& rm -rf /var/lib/apt/lists/*

COPY requirements.txt *.py /

RUN python3 -m pip install --no-cache-dir -r /requirements.txt

ENTRYPOINT ["python3", "/model_scan.py"]

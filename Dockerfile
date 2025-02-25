FROM python:3.13-slim@sha256:0911c0f1ca0214c41de3974ef4bda59fe2eb5c54da27bf0ab008bf87a8b682be

RUN apt-get -y update \
	&& apt-get install -y git \
	&& rm -rf /var/lib/apt/lists/*

COPY requirements.txt *.py /

RUN python3 -m pip install --no-cache-dir -r /requirements.txt

ENTRYPOINT ["python3", "/model_scan.py"]

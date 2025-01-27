FROM python:3.13-slim@sha256:026dd417a88d0be8ed5542a05cff5979d17625151be8a1e25a994f85c87962a5

RUN apt-get -y update \
	&& apt-get install -y git \
	&& rm -rf /var/lib/apt/lists/*

COPY requirements.txt *.py /

RUN python3 -m pip install --no-cache-dir -r /requirements.txt

ENTRYPOINT ["python3", "/model_scan.py"]

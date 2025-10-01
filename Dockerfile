FROM python:3.13.7-slim@sha256:00c80da2f67c963024c9593a560833235ece8449003a366947dec0025124d82d

RUN apt-get -y update \
	&& apt-get install -y git \
	&& rm -rf /var/lib/apt/lists/*

COPY requirements.txt *.py /

RUN python3 -m pip install --no-cache-dir -r /requirements.txt

ENTRYPOINT ["python3", "/model_scan.py"]

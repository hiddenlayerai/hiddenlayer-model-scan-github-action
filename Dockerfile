FROM python:3.12-slim@sha256:ad48727987b259854d52241fac3bc633574364867b8e20aec305e6e7f4028b26

RUN apt-get -y update \
	&& apt-get install -y git \
	&& rm -rf /var/lib/apt/lists/*

COPY requirements.txt *.py /

RUN python3 -m pip install --no-cache-dir -r /requirements.txt

ENTRYPOINT ["python3", "/model_scan.py"]

FROM debian:stable-slim
RUN apt update && apt install -y \
    gcc \
    python3 \
    python3-pip \
    git

# Install theharvester from git along with deps 
# WORKDIR /usr/share
RUN git clone https://github.com/zhanchi5/lsass_dumper.git
#RUN apt install python3-dev openssl-dev libffi-dev gcc && pip3 install --upgrade pip
RUN pip3 install -r lsass_dumper/requirements.txt


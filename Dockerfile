FROM ubuntu:20.04

RUN apt-get update && apt-get install -y \
 curl \
 gnupg \
 lsb-release \
 iproute2 \
 iputils-ping \
 tcpdump \
 && curl -s https://deb.frrouting.org/frr/keys.gpg | tee /usr/share/keyrings/fr>
 && echo "deb [signed-by=/usr/share/keyrings/frrouting.gpg] https://deb.frrouti>
 && apt-get update && apt-get install -y frr

CMD ["sleep", "infinity"]

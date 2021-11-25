ARG BUILD_FROM
FROM alpine:latest

ENV LANG C.UTF-8

# install python
RUN apk add --no-cache python3
RUN apk add py-pip

RUN mkdir /device_tracker
WORKDIR /device_tracker

RUN wget https://github.com/Smekl/Device-Tracker/archive/refs/tags/0.5.tar.gz
RUN tar xzf 0.5.tar.gz --strip-components=1
RUN apk add libpcap
RUN pip install scapy requests
RUN chmod +x hotfixes/scapy.sh && ./hotfixes/scapy.sh
RUN chmod +x ./run.sh
CMD [ "./run.sh" ]

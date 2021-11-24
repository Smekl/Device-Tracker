ARG BUILD_FROM
FROM $BUILD_FROM

ENV LANG C.UTF-8

# install python
RUN apk add --no-cache python3

RUN mkdir /device_tracker
WORKDIR /device_tracker

RUN wget https://github.com/Smekl/Device-Tracker/archive/refs/tags/0.2.tar.gz
RUN tar xzf 0.2.tar.gz --strip-components=1
RUN apk add libpcap
RUN pip3 install scapy requests
RUN chmod +x hotfixes/scapy.sh && ./hotfixes/scapy.sh
RUN chmod +x ./run.sh
CMD [ ./run.sh ]

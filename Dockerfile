ARG BUILD_FROM
FROM $BUILD_FROM

ENV LANG C.UTF-8

# install python
RUN apk add --no-cache python3
RUN apk add py-pip

RUN mkdir /device_tracker
WORKDIR /device_tracker

COPY . .
RUN apk add libpcap
RUN pip install scapy requests websocket-client
RUN chmod +x hotfixes/scapy.sh && ./hotfixes/scapy.sh
RUN chmod +x ./run.sh
CMD [ "./run.sh" ]

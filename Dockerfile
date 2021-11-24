FROM alpine:3.15

RUN mkdir /device_tracker
WORKDIR /device_tracker

RUN wget https://github.com/Smekl/Device-Tracker/archive/refs/tags/0.1.tar.gz
RUN tar xzf 0.1.tar.gz

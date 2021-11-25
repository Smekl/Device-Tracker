#!/bin/bash

ARCH=`dpkg --print-architecture`
DOCKER_NAME=haservices/$ARCH-device-tracker:1.0
#BUILD_FROM=ghcr.io/hassio-addons/base/$ARCH:10.2.3
BUILD_FROM=homeassistant/$ARCH-base:3.12

cd ../

# prepare config
mkdir -p /tmp/data
cp options.json /tmp/data

sudo docker rmi -f $DOCKER_NAME
sudo docker build -t $DOCKER_NAME --build-arg BUILD_FROM=$BUILD_FROM -f tests/Dockerfile .

if [[ $? -ne 0 ]]; then
    exit $?
fi

sudo docker run --network host -v /tmp/data:/data -t -i $DOCKER_NAME /bin/bash

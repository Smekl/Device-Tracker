#!/bin/bash

ARCH=`dpkg --print-architecture`
DOCKER_NAME=haservices/device-tracker:1.0
BUILD_FROM=homeassistant/$ARCH-base:latest

cd ../

# prepare config
mkdir -p /tmp/data
cp options.json /tmp/data

sudo docker build -t $DOCKER_NAME --build-arg BUILD_FROM=$BUILD_FROM -f tests/Dockerfile .
sudo docker run --network host -v /tmp/data:/data -t -i $DOCKER_NAME sh

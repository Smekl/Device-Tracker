#!/bin/bash

DOCKER_NAME=haservices/device-tracker:1.0

cd ../

# prepare config
mkdir -p /tmp/data
cp options.json /tmp/data

sudo docker build -t $DOCKER_NAME -f tests/Dockerfile .
sudo docker run --network host -v /tmp/data:/data -t -i $DOCKER_NAME sh

#!/bin/sh

echo Starting Device Tracker

CONFIG_PATH=
if [ -f "/.dockerenv" ]; then
    CONFIG_PATH=/data/options.json
else
    CONFIG_PATH=options.json
fi

echo token start
echo $SUPERVISOR_TOKEN
echo token end
python3 track.py --config $CONFIG_PATH --token $SUPERVISOR_TOKEN

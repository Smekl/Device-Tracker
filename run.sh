#!/bin/sh

CONFIG_PATH=
if [ -f "/.dockerenv" ]; then
    CONFIG_PATH=/data/options.json
else
    CONFIG_PATH=options.json
fi

python track.py --config $CONFIG_PATH

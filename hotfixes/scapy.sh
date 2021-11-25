#!/bin/sh

FILEPATH=`python3 -c "import scapy,os; print(os.path.join(scapy.__path__[0], 'libs/winpcapy.py'))"`

if [ -f "/.dockerenv" ]; then
    echo Fixing scapy bug $FILEPATH
	sed -i -e 's#find_library("pcap")#"/usr/lib/libpcap.so.1"#g' $FILEPATH

	echo Done
fi

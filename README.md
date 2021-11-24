# Device Tracker

Will track DHCP requests from your selected devices and report it to Home Assistant.<br>
Should be much faster than the Home Assistant phone app.<br>

## Things To Do
1. `sudo setcap cap_net_admin,cap_net_raw+eip /bin/python3.8`
2. pip3 install scapy

## Install as a Service
1. Fix file in `systemd/device-tracker.service` according to your filesystem
2. run `sudo cp systemd/device-tracker.service /etc/systemd/system`
3. run `sudo systemctl start device-tracker.service` 
4. test if running `ps -fade | grep track.py`
5. enable on startup `sudo systemctl enable device-tracker.service`

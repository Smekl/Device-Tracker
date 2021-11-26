# Home Assistant Add-on: Device Tracker

## Installation
1. Navigate in your Home Assistant frontend to **Supervisor -> Add-on Store**.
2. Add `https://github.com/Smekl/Device-Tracker` to your repositories
3. Find `Device Tracker` and click it
4. Click `Install` in the add-on page

## How to use
This addon is currently meant to run along with `Nodered`.<br>
*Device Tracker* will monitor and notify *NodeRED* about new devices that recently joined your local network.<br>
A little bit of configuration is required - <br>
1. `url` - specify the full url to send notifications to - i.e `https://localhost:1880`
2. `username` - username for nodered web ui
2. `password` - password for nodered web ui
<br>
if your nodered has no username or password - **leave this field black**<br>

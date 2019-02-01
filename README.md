# AWS VPN config parser

## Description

This script parses AWS VPN config for mikrotik and creates mikrotik configuration script. It works only for configuration with bgp.

If you set parameter "output", then script generate files for each tunnel. Default output to std.

> You need set "Propogate routes" in AWS console

## Requrements
- python 3

## Parameters
```
usage: dynamic-config.py [-h] --config CONFIG [--wan-interface WAN_INTERFACE]
                         [--lan-interface LAN_INTERFACE]
                         [--local-net LOCAL_NET] [--remote-net REMOTE_NET]
                         [--comment COMMENT] [--local-as LOCAL_AS]
                         [--output OUTPUT]

optional arguments:
  -h, --help            show this help message and exit
  --config CONFIG       path to config file
  --wan-interface WAN_INTERFACE
                        wan interface for this connection with static ip
                        (default: sfp1)
  --lan-interface LAN_INTERFACE
                        bridge interface for firewall rules (default: br0)
  --local-net LOCAL_NET
                        local network (default: 192.168.0.0/24)
  --remote-net REMOTE_NET
                        aws inner network (default: 10.0.0.0/24)
  --comment COMMENT     comment for mark changing
  --local-as LOCAL_AS   local AS for bgp (default: 65000)
  --output OUTPUT       generate script for each tunnel {{ config
                        }}_Tunnel##.rsc (default output: std)
```
## Usage example
```
 ./dynamic-config.py --config vpn-config.txt --wan-interface sfp1 --lan-interface br0 --local-net 192.168.1.0/24 --remote-net 10.0.1.0/24 --local-as 65000
 ```
#!/bin/python3

import json
import argparse
def readDataFromConfig(config_path):
    with open(config_path) as f:
        data = f.readlines()

    for i in range(0, len(data)):
        if "! IPSec Tunnel #1" in data[i]:
            strTun1 = i
        if "! IPSec Tunnel #2" in data[i]:
            strTun2 = i
    return parseTunnel(data[strTun1:strTun2]), parseTunnel(data[strTun2:])

def parseTunnel(data):
    tunnel = {}
    for i in range(0, len(data)):
        if "! IPSec Tunnel #" in data[i]:
            tunnel["name"] = data[i].replace("! IPSec ", '').strip().replace(' ', '_')
        if "b. Name: ipsec-vpn-" in data[i]:
            tunnel["ipsec-vpn-name"] = data[i].replace("b. Name: ", '').strip()
        if "b. SA Src. Address: " in data[i]:
            tunnel['sa-src'] = data[i].replace("b. SA Src. Address: ", '').strip()
        if "c. SA Dst. Address: " in data[i]:
            tunnel['sa-dst'] = data[i].replace("c. SA Dst. Address: ", '').strip()
        if "a. Src. Address: " in data[i]:
            tunnel['ipsec-src'] = data[i].replace("a. Src. Address: ", '').strip()
        if "b. Dst. Address: " in data[i]:
            tunnel['ipsec-dst'] = data[i].replace("b. Dst. Address: ", '').strip()
        if "c. Secret: " in data[i]:
            tunnel['secret'] = data[i].replace("c. Secret: ", '').strip()
        if "b. Name: BGP-vpn-" in data[i]:
            tunnel['bgp-name'] = data[i].replace("b. Name: ", '').strip()
        if "d. Remote AS: " in data[i]:
            tunnel['remote-as'] = data[i].replace("d. Remote AS: ", '').strip()
    return tunnel
    print(json.dumps(tunnel, indent=4))

def generateMikrotikScript(dt):
    string = []
    # tunnel CIDR
    string.append("/ip addr add comment={comment} address={src}/30 interface={interface}".format(comment=dt["comment"], src=dt['ipsec-src'], interface=dt["wan-interface"]))
    # ipsec proposal
    string.append('/ip ipsec proposal add auth-algorithms=sha1 comment="AWS PROPOSAL" enc-algorithms=aes-128-cbc lifetime=1h name={name} pfs-group=modp1024'.format(
        comment=dt["comment"], name=dt['ipsec-vpn-name']))
    # ipsec policy
    string.append('/ip ipsec policy add comment={comment} src-address=0.0.0.0/0  src-port=any dst-address={remotenet} dst-port=any  protocol=all action=encrypt level=require   ipsec-protocols=esp  tunnel=yes sa-src-address={publicip} sa-dst-address={remotepub}  proposal={name}'.format(
        comment=dt["comment"], remotenet=dt["remote-net"], publicip=dt["sa-src"], remotepub=dt["sa-dst"], name=dt['ipsec-vpn-name']))
    string.append('/ip ipsec policy add comment={comment} src-address=0.0.0.0/0  src-port=any dst-address={ipsecdst} dst-port=any protocol=all action=encrypt level=require ipsec-protocols=esp  tunnel=yes sa-src-address={publicip} sa-dst-address={remotepub}  proposal={name}'.format(
        comment=dt["comment"], ipsecdst=dt["ipsec-dst"], publicip=dt["sa-src"], remotepub=dt["sa-dst"], name=dt['ipsec-vpn-name']))
    # ipsec profile
    string.append('/ip ipsec peer profile add name={name} nat-traversal=no proposal-check=obey hash-algorithm=sha1 enc-algorithm=aes-128 dh-group=modp1024 lifetime=8h lifebytes=0 dpd-interval=10s dpd-maximum-failures=3'.format(name=dt['name']))
    # ipsec peer
    string.append('/ip ipsec peer add comment={comment} address={remotepub}/32 local-address={publicip} passive=no port=500 auth-method=pre-shared-key secret={secret} generate-policy=no exchange-mode=main send-initial-contact=yes profile={name}'.format(
        comment=dt["comment"], secret=dt["secret"], publicip=dt["sa-src"], remotepub=dt["sa-dst"], name=dt['name']))
    # firewall rules
    string.append('/ip firewall filter add comment={comment} chain=input action=accept protocol=ipsec-esp src-address={remotepub} dst-address={publicip} in-interface={wan_interface} place-before=1'.format(comment=dt["comment"], wan_interface=dt["wan-interface"], publicip=dt["sa-src"], remotepub=dt["sa-dst"]))
    string.append('/ip firewall filter add comment={comment} chain=input action=accept protocol=udp src-address={remotepub} dst-address={publicip} in-interface={wan_interface} src-port=500  dst-port=500   place-before=1'.format(comment=dt["comment"], wan_interface=dt["wan-interface"], publicip=dt["sa-src"], remotepub=dt["sa-dst"]))
    string.append('/ip firewall filter add comment={comment} chain=input action=accept protocol=tcp src-address={ipsec_dst} dst-address={ipsec_src} dst-port=179   place-before=1'.format(comment=dt["comment"], ipsec_dst=dt["ipsec-dst"], ipsec_src=dt["ipsec-src"]))
    string.append('/ip firewall filter add comment={comment} chain=forward action=accept src-address={remotenet} in-interface={wan_interface}'.format(comment=dt["comment"], remotenet=dt["remote-net"], wan_interface=dt["wan-interface"]))
    string.append('/ip firewall filter add comment={comment} chain=forward action=accept dst-address={remotenet} in-interface={local_interface}'.format(comment=dt["comment"], remotenet=dt["remote-net"], local_interface=dt["local-interface"]))
    # nat rule
    # critically important to AWS connectivity that this rule be ahead of "masquerade".
    string.append("/ip firewall nat add comment={comment} chain=srcnat action=src-nat to-addresses={localnet} dst-address={remotenet} place-before=0".format(comment=dt["comment"], localnet=dt["local-net"], remotenet=dt['remote-net']))
    string.append("/ip firewall nat add comment={comment} chain=dstnat action=accept src-address={remotenet} in-interface={wan_interface} place-before=0".format(comment=dt["comment"], remotenet=dt['remote-net'], wan_interface=dt["wan-interface"]))
    # routing bgp
    string.append('/routing bgp instance set default disabled=yes')
    string.append('/routing bgp instance add comment={comment} as={local_as} client-to-client-reflection=no name={name} redistribute-static=yes router-id={ipsec_src}'.format(comment=dt["comment"], local_as=dt['local-as'], ipsec_src=dt['ipsec-src'], name=dt['name']))
    string.append('/routing bgp network add comment={comment} network={localnet}'.format(comment=dt["comment"], localnet=dt['local-net']))
    string.append('/routing bgp peer add comment={comment} hold-time=30s instance={name} remote-address={ipsecdst} remote-as={remoteas}'.format(comment=dt["comment"], name=dt['name'],
                    ipsecdst=dt["ipsec-dst"], remoteas=dt["remote-as"]))
    if(dt['output'] and dt['output'] != ''):
        with open(dt['output'] + '_' + dt['name'] + '.rsc', 'w') as f:
            for line in string:
                f.write(line + '\n')
    else:
        for line in string:
            print(line)

def printHelp():
    print("This is script for converting aws config to mikrotik script")
def setPermanentInfo():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', action='store', type=str, help='path to config file', required=True)
    parser.add_argument('--wan-interface', action='store', type=str, help='wan interface for this connection with static ip (default: sfp1)', default='sfp1')
    parser.add_argument('--lan-interface', action='store', type=str, help='bridge interface for firewall rules (default: br0)', default='br0')
    parser.add_argument('--local-net', action='store', type=str, help='local network (default: 192.168.0.0/24)', default='192.168.0.0/24')
    parser.add_argument('--remote-net', action='store', type=str, help='aws inner network (default: 10.0.0.0/24)', default='10.0.0.0/24')
    parser.add_argument('--comment', action='store', type=str, help='comment for mark changing', default='AWS-VPN')
    parser.add_argument('--local-as', action='store', type=str, help='local AS for bgp (default: 65000)', default='65000')
    parser.add_argument('--output', action='store', type=str, help='generate script for each tunnel {{ config }}_Tunnel##.rsc (default output: std)')
    par = parser.parse_args()
    if(par.config == ''):
        print("Choose config file")
        parser.print_help()
        exit(1)
    permanentInfo = {
        "config": par.config,
        "wan-interface": par.wan_interface,
        "local-interface": par.lan_interface,
        "local-net": par.local_net,
        "remote-net": par.remote_net,
        "comment": par.comment,
        "local-as": par.local_as,
        "output": par.output
    }
    return permanentInfo


if __name__ == "__main__":
    permanentInfo = setPermanentInfo()
    for tun in readDataFromConfig(permanentInfo['config']):
        configuration = {}
        configuration.update(tun)
        configuration.update(permanentInfo)
        print(json.dumps(configuration, indent=4))
        generateMikrotikScript(configuration)

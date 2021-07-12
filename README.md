# openvpn-pki-telegram

- [openvpn-pki-telegram](#openvpn-pki-telegram)
  - [Overview](#overview)
  - [Prerequisite](#prerequisite)
  - [Install Dependencies](#install-dependencies)
  - [Create CA](#create-ca)
  - [Create Server Certificate & Server Configuration](#create-server-certificate--server-configuration)
    - [Enable and Start OpenVPN Server](#enable-and-start-openvpn-server)
  - [Create Client Certificate & Client Configuration to Telegram](#create-client-certificate--client-configuration-to-telegram)


## Overview
Automate OpenVPN server, client config creation

## Prerequisite
Installed these packages (tested on Ubuntu 20.04 LTS):
- python3
- openvpn

## Install Dependencies
```bash
pip3 install -r requirements.txt
```

## Create CA
```bash
python3 openvpn.py createca $YOUR_CA_NAME
```

## Create Server Certificate & Server Configuration
```bash
python3 openvpn.py createservercert $YOUR_CA_NAME $SERVER_COMMON_NAME
```
### Enable and Start OpenVPN Server
```bash
systemctl enable openvpn@server
systemctl start openvpn@server
```

## Create Client Certificate & Client Configuration to Telegram
```bash
python3 openvpn.py adduser $YOUR_CA_NAME $CLIENT_COMMON_NAME $DAYS_TO_EXPIRE
```

#!/bin/bash

# install rpms
yum install -y epel-release
yum install -y openvpn
yum install -y easy-rsa-3.0.3-3.fc29.noarch.rpm # TODO: attach the file in install_pkg

# initial settings
mkdir -p /etc/openvpn/easy-rsa/keys
cp -rf /usr/share/easy-rsa/3.0.3/* /etc/openvpn/easy-rsa
cp server.conf /etc/openvpn # TODO: attach the file in install_pkg
cp client.conf /etc/openvpn	# TODO: attach the file in install_pkg

cd /etc/openvpn/easy-rsa
./easyrsa init-pki
./easyrsa build-ca nopass

rm /etc/openvpn/server_*

cd /etc/openvpn/easy-rsa
mkdir /etc/openvpn/ccd
mkdir /etc/openvpn/easy-rsa/keys/

# build server
./easyrsa build-server-full server nopass
openssl dhparam -out dh2048.pem 2048
/usr/sbin/openvpn --genkey --secret ta.key

cp pki/ca.crt /etc/openvpn/
cp dh2048.pem /etc/openvpn
cp ta.key /etc/openvpn/

cp pki/issued/server.crt /etc/openvpn/
cp pki/private/server.key /etc/openvpn/

cp pki/ca.crt /etc/openvpn/easy-rsa/keys/
cp dh2048.pem /etc/openvpn/easy-rsa/keys/
cp ta.key /etc/openvpn/easy-rsa/keys/

cp /etc/openvpn/client.conf /etc/openvpn/easy-rsa/keys/

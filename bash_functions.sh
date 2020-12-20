#!/bin/bash

#WORK_DIR=/root/SDWanManager/ZGW # folder
#ZONE_SERVERS_DIR=${WORK_DIR}/servers # folder

WORK_DIR=/usr/local/bin/CellularServer_Pkg/SDWanManager/ZGW/dist/SDWanAgent # folder
ZONE_SERVERS_DIR=${WORK_DIR}/servers # folder

IPS_FILEPATH=${WORK_DIR}/ips # file
ZONE_CLIENTS_FILEPATH=${WORK_DIR}/ZoneClients # file
ALL_CLIENTS_FILEPATH=${WORK_DIR}/AllClients # file

OPENVPN_SERVER_CLASS_A_B=10.9

init (){

    NMS_PUBLIC_IP=$1

    echo "install net-tools + tcpdump ..."
	if ! yum list installed | grep net-tools > /dev/null;then
		sudo yum -y install net-tools
		sudo yum -y install tcpdump
	else
	    echo "already installed!"
	fi

    echo "config eth1..."
    if ! ls /etc/sysconfig/network-scripts/ | grep "ifcfg-eth1" > /dev/null;then
        echo 'DEVICE=eth1
ONBOOT=yes
TYPE="Ethernet"
NM_CONTROLLED=no
IPADDR=100.1.1.254
NETMASK=255.255.255.0
IPV6INIT=no
MTU=1450' >  /etc/sysconfig/network-scripts/ifcfg-eth1
        service network restart
    else
        source /etc/sysconfig/network-scripts/ifcfg-eth1
	    echo "already have eth1 - IPADDR: ${IPADDR}"
    fi

	echo "install python3..."
	if ! yum list installed | grep python3 > /dev/null;then
		sudo yum -y install python3
		pip3 install requests
		pip3 install netifaces
	else
	    echo "already installed!"
	fi

    echo "Enable ip-forward"
	echo 1 >> /proc/sys/net/ipv4/ip_forward

    echo "Enable SNAT"
	if ! iptables -t nat -L | grep MASQUERADE > /dev/null;then
		iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
	else
	    echo "already Enabled!"
	fi

    echo "install openvpn-server (epelrelease+openvpn+easyrsa)"
	if ! yum list installed | grep openvpn > /dev/null;then
		chmod +x OpenvpnServerInstaller.sh
		./OpenvpnServerInstaller.sh
	else
	    echo "already installed!"
	fi

    echo "create VRF table"
	if ! cat /etc/iproute2/rt_tables | grep VRF > /dev/null; then
		echo 200 VRF >> /etc/iproute2/rt_tables
	else
	    echo "already exists!"
	fi

	echo "update rule"
	if ! echo $(ip rule) | grep "from all lookup VRF" > /dev/null; then
		ip rule add from all lookup VRF
	else
	    echo "already exists!"
	fi

	echo "stop firewall"
	systemctl stop firewalld

    echo "getting ips"
	zgw_public_ip=$(ifconfig eth0 | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1')
	zgw_local_ip=$(ifconfig eth1 | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1')

    echo "save ips"
	echo "${zgw_public_ip} ${zgw_local_ip} ${NMS_PUBLIC_IP}" > ${IPS_FILEPATH}
	echo "Done init process"
}

CreateOVPNfile (){
	CLIENT_NAME=$1

    cd /etc/openvpn/easy-rsa/keys/
	#file check exists
	for i in "${CLIENT_NAME}.conf" "${CLIENT_NAME}.key" "${CLIENT_NAME}.crt" "ca.crt" "ta.key"; do
	    if [[ ! -f ${i} ]]; then
	        echo " The file $i does not exist"
	        exit 1
	    fi

	    if [[ ! -r ${i} ]]; then
	        echo " The file $i is not readable."
	        exit 1
	    fi
	done

	# Generate client config
	cat > ${CLIENT_NAME}.ovpn <<EOF
$(cat ${CLIENT_NAME}.conf)
<key>
$(cat ${CLIENT_NAME}.key)
</key>
<cert>
$(cat ${CLIENT_NAME}.crt)
</cert>
<ca>
$(cat ca.crt)
</ca>
<tls-auth>
$(cat ta.key)
</tls-auth>
EOF
}

GenerateVPNClient (){
	TUN_ID=$1
	SERVER_IP=$2
	CLIENT_IP=$3
	CLIENT_NAME=client_${TUN_ID}
	port=$((50000 + $TUN_ID))

    cd /etc/openvpn/easy-rsa
	./easyrsa build-client-full ${CLIENT_NAME} nopass
	cp pki/issued/${CLIENT_NAME}.crt /etc/openvpn/easy-rsa/keys/
	cp pki/private/${CLIENT_NAME}.key /etc/openvpn/easy-rsa/keys/

    cd /etc/openvpn/easy-rsa/keys/
	cp /etc/openvpn/client.conf ${CLIENT_NAME}.conf
	sed -i "s/dev tun.*/dev tun${TUN_ID}/" ${CLIENT_NAME}.conf
	sed -i "s/remote.*/remote ${SERVER_IP} $port/" ${CLIENT_NAME}.conf
	sed -i "s/local.*/local ${CLIENT_IP}/" ${CLIENT_NAME}.conf
	sed -i "/ca .*/d" ${CLIENT_NAME}.conf
	sed -i "/key .*/d" ${CLIENT_NAME}.conf
	sed -i "/cert .*/d" ${CLIENT_NAME}.conf
	echo "remote-cert-tls server" >> ${CLIENT_NAME}.conf
	echo "tls-auth ta.key 1" >> ${CLIENT_NAME}.conf
	echo "key-direction 1" >> ${CLIENT_NAME}.conf
	echo "--pull-filter ignore redirect-gateway" >> ${CLIENT_NAME}.conf

	CreateOVPNfile ${CLIENT_NAME}
}

GenerateVPNServer (){
	TUN_ID=$1
	SERVER_NAME=server_${TUN_ID}
	port=$((50000 + $TUN_ID))
	
	cd /etc/openvpn
	cp server.conf ${SERVER_NAME}.conf
	sed -i "s/dev tun.*/dev tun${TUN_ID}/" ${SERVER_NAME}.conf
	sed -i "s/server 10.8.0.0 255.255.255.0/server ${OPENVPN_SERVER_CLASS_A_B}.${TUN_ID}.0 255.255.255.0/" ${SERVER_NAME}.conf
	sed -i "s/port 1194/port $port/" ${SERVER_NAME}.conf
	systemctl enable openvpn@${SERVER_NAME}
}

TunnelUp (){
	TUN_ID=$1
	SERVER_IP=$2
	CLIENT_IP=$3
	SERVER_NAME=server_${TUN_ID}

	GenerateVPNServer ${TUN_ID}
	GenerateVPNClient ${TUN_ID} ${SERVER_IP} ${CLIENT_IP}

	systemctl start openvpn@${SERVER_NAME}
}

ClientUp (){
	TUN_ID=$1

    if ! echo $(ip link show) | grep "tun${TUN_ID}:" > /dev/null; then
        openvpn "/etc/openvpn/easy-rsa/keys/client_${TUN_ID}.ovpn" > "/etc/openvpn/easy-rsa/keys/client_${TUN_ID}.logs" &
        sleep 3
        iptables -t nat -A POSTROUTING -o tun${TUN_ID} -j MASQUERADE
    else
        echo "tun${TUN_ID} already up"
    fi

}

AddRoute (){
	dst_ip=$1
	gw_ip=$2
	vrf_table=$(ip route list table VRF)

	echo "updating routes"
	if echo ${vrf_table} | grep ${dst_ip} > /dev/null; then
		if ! echo ${vrf_table} | grep "${dst_ip} via ${gw_ip}" > /dev/null; then
			echo "ip route change ${dst_ip} via ${gw_ip} table VRF"
			ip route change ${dst_ip} via ${gw_ip} table VRF
		fi
	else
		echo "ip route add ${dst_ip} via ${gw_ip} table VRF"
		ip route add ${dst_ip} via ${gw_ip} table VRF
	fi
}

RemoveDeadRoutes (){
    all_clients=$(cat ${ALL_CLIENTS_FILEPATH})

    echo "remove dead routes"
    for client_ip in $(ip route list table VRF | cut -d ' ' -f 1); do
        if [[ ! ${client_ip} = "default" ]]; then
            if ! echo ${all_clients} | grep ${client_ip} > /dev/null; then
                echo "ip route del ${client_ip} table VRF"
                ip route del ${client_ip} table VRF
            fi
        fi
    done
}

ResetZGW (){

    echo "reset openvpn files:"
    cd /etc/openvpn/
    # reset servers
    rm -rf server_*
    cd /etc/openvpn/easy-rsa/keys/
    # reset clients
    rm -rf client_*

    echo "reset openvpn services"
    for pid in $(ps -ef | grep "server_.*.conf" | awk '{ print $2 }'); do
        echo "kill $pid"
        kill $pid
    done
    for pid in $(ps -ef | grep "client_.*.ovpn" | awk '{ print $2 }'); do
        echo "kill $pid"
        kill $pid
    done

    echo "reset SDWanAgent files:"
    cd /root/SDWanManager/ZGW
    rm -rf AllClients
    rm -rf ZoneClients
    rm -rf tunnels.json
    rm -rf logs/*

}


if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    $@
fi

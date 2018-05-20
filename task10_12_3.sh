#!/usr/bin/env bash

	#font
	n=$(tput sgr0);
	bold=$(tput bold);

	#path
	way=$(cd "$(dirname "$0")"; pwd)
	source "$way/config"

echo ${bold}"Work dir - $way"${n}
MAC=52:54:00:`(date; cat /proc/interrupts) | md5sum | sed -r 's/^(.{6}).*$/\1/; s/([0-9a-f]{2})/\1:/g; s/:$//;'`

echo ${bold}"Generating libvirt-networks"${n}
mkdir -p "$way/networks"

#external net
echo ${bold}"external.xml"${n}
cat << external > $way/networks/$EXTERNAL_NET_NAME.xml
<network>
  <name>$EXTERNAL_NET_NAME</name>
  <forward mode="nat">
    <nat>
      <port start='1024' end='65535'/>
    </nat>
  </forward>
  <ip address='$EXTERNAL_NET_HOST_IP' netmask='$EXTERNAL_NET_MASK'>
    <dhcp>
      <range start='$EXTERNAL_NET.2' end='$EXTERNAL_NET.254'/>
      <host mac='$MAC' name='$VM1_NAME' ip='$VM1_EXTERNAL_IP'/>
    </dhcp>
  </ip>
</network>

external

cat $way/networks/$EXTERNAL_NET_NAME.xml

#internal net
echo ${bold}"internal.xml"${n}
cat << internal > $way/networks/$INTERNAL_NET_NAME.xml
<network>
  <name>$INTERNAL_NET_NAME</name>
</network>

internal

cat $way/networks/$INTERNAL_NET_NAME.xml

#management net
echo ${bold}"management.xml"${n}
#
#remove forward after test
# <forward dev='eno3' mode='route'>
#    <interface dev='eno3'/>
#  </forward>
#
cat << management > $way/networks/$MANAGEMENT_NET_NAME.xml
<network>
  <name>$MANAGEMENT_NET_NAME</name>
    <ip address='$MANAGEMENT_HOST_IP' netmask='$MANAGEMENT_NET_MASK'/>
</network>

management

cat $way/networks/$MANAGEMENT_NET_NAME.xml
sleep 3

echo ${bold}"Activating networks"${n}
virsh net-define $way/networks/$EXTERNAL_NET_NAME.xml
virsh net-start $EXTERNAL_NET_NAME
virsh net-define $way/networks/$INTERNAL_NET_NAME.xml
virsh net-start $INTERNAL_NET_NAME
virsh net-define $way/networks/$MANAGEMENT_NET_NAME.xml
virsh net-start $MANAGEMENT_NET_NAME

#ssh
echo ${bold}"Generating SSH-keys"${n}
SSH_KEY=$(echo "$SSH_PUB_KEY" | sed 's/.pub//')
echo "$SSH_KEY"
mkdir -p $(dirname $SSH_PUB_KEY)
echo -e "n" | ssh-keygen -t rsa -N "" -f $SSH_KEY

#create cert
cert_dir="${way}/docker/certs"
mkdir -p $cert_dir
openssl genrsa -out ${cert_dir}/root.key 4096
openssl req -x509 -newkey rsa:4096 -passout pass:1234 -keyout ${cert_dir}/root.key -out ${cert_dir}/root.crt -subj "/C=UA/O=VM/CN=${VM1_NAME}ca" 
openssl genrsa -out ${cert_dir}/web.key 4096
openssl req -new -key ${cert_dir}/web.key -out ${cert_dir}/web.csr -subj "/C=UA/O=VM/CN=${VM1_NAME}" \
	 -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:${VM1_NAME},DNS:${VM1_EXTERNAL_IP}"))
openssl x509 -req -in ${cert_dir}/web.csr -CA ${cert_dir}/root.crt -passin pass:1234 -CAkey ${cert_dir}/root.key \
	-CAcreateserial -out ${cert_dir}/web.crt -days 365 -extfile <(printf "subjectAltName=DNS:${VM1_NAME},DNS:${VM1_EXTERNAL_IP}")
cat ${cert_dir}/root.crt >> ${cert_dir}/web.crt

#nginx conf
nginx_dir="${way}/docker/etc"
mkdir -p $nginx_dir
cat << nginxconf > $nginx_dir/nginx.conf
server {
	listen 443 ssl;
	ssl on;
	ssl_certificate /etc/ssl/web.crt;
	ssl_certificate_key /etc/ssl/web.key;
	server_name ${VM1_NAME};
location / {
	proxy_pass http://$VM2_VXLAN_IP:$APACHE_PORT;
	}
	error_page 497 =444 @close;
	location @close {
			return 0;
			}
	}
nginxconf

echo -e ${bold}"\nDownload Ubuntu cloud image and prepare disk"${n}
mkdir -p /var/lib/libvirt/images/$VM1_NAME /var/lib/libvirt/images/$VM2_NAME
wget -O $VM1_HDD $VM_BASE_IMAGE
cp $VM1_HDD $VM2_HDD
sleep 3
echo ${bold}"Creating config-drives"${n}
#meta-data vm1
mkdir -p "$way/config-drives/$VM1_NAME-config"
echo ${bold}"meta-data $VM1_NAME"${n}
cat << metadatavm1 > $way/config-drives/$VM1_NAME-config/meta-data
hostname: $VM1_NAME
local-hostname: $VM1_NAME
network-interfaces: |
  auto $VM1_EXTERNAL_IF
  iface $VM1_EXTERNAL_IF inet dhcp
  dns-nameservers $VM_DNS

  auto $VM1_INTERNAL_IF
  iface $VM1_INTERNAL_IF inet static
  address $VM1_INTERNAL_IP
  network $INTERNAL_NET_IP
  netmask $INTERNAL_NET_MASK
  broadcast ${INTERNAL_NET}.255

  auto $VM1_MANAGEMENT_IF
  iface $VM1_MANAGEMENT_IF inet static
  address $VM1_MANAGEMENT_IP
  network $MANAGEMENT_NET_IP
  netmask $MANAGEMENT_NET_MASK
  broadcast ${MANAGEMENT_NET}.255

metadatavm1

cat $way/config-drives/$VM1_NAME-config/meta-data

#meta-data vm2
mkdir -p "$way/config-drives/$VM2_NAME-config"
echo ${bold}"meta-data $VM2_NAME"${n}
cat << metadatavm2 > $way/config-drives/$VM2_NAME-config/meta-data
hostname: $VM2_NAME
local-hostname: $VM2_NAME
network-interfaces: |
  auto $VM2_INTERNAL_IF
  iface $VM2_INTERNAL_IF inet static
  address $VM2_INTERNAL_IP
  network $INTERNAL_NET_IP
  netmask $INTERNAL_NET_MASK
  broadcast ${INTERNAL_NET}.255
  gateway ${VM1_INTERNAL_IP}
  dns-nameservers $VM_DNS

  auto $VM2_MANAGEMENT_IF
  iface $VM2_MANAGEMENT_IF inet static
  address $VM2_MANAGEMENT_IP
  network $MANAGEMENT_NET_IP
  netmask $MANAGEMENT_NET_MASK
  broadcast ${MANAGEMENT_NET}.255

metadatavm2

cat $way/config-drives/$VM2_NAME-config/meta-data

#user-data vm1
echo ${bold}"user-data $VM1_NAME"${n}
cat << userdatavm1 > $way/config-drives/$VM1_NAME-config/user-data
#cloud-config
password: qwerty
chpasswd: { expire: False }
ssh_authorized_keys:
  - $(cat  $SSH_PUB_KEY)
apt_update: true
packages:
 - apt-transport-https
 - ca-certificates
 - curl
 - software-properties-common
runcmd:
  - echo "1" > /proc/sys/net/ipv4/ip_forward
  - iptables -F
  - iptables -t nat -F
  - iptables -t mangle -F
  - iptables -A FORWARD -i $VM1_EXTERNAL_IF -o $VM1_INTERNAL_IF -j ACCEPT
  - iptables -A FORWARD -i $VM1_INTERNAL_IF -o $VM1_EXTERNAL_IF -j ACCEPT
  - iptables -t nat -A POSTROUTING -s $INTERNAL_NET_IP/24 -o $VM1_EXTERNAL_IF -j MASQUERADE
  - ip link add $VXLAN_IF type vxlan id $VID remote $VM2_INTERNAL_IP local $VM1_INTERNAL_IP dstport 4789
  - ip link set $VXLAN_IF up
  - ip addr add $VM1_VXLAN_IP/24 dev $VXLAN_IF
  - curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
  - add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu xenial stable"
  - apt update
  - apt install -y docker-ce
  - systemctl start docker
  - mkdir -p /srv/certs /srv/etc $NGINX_LOG_DIR
  - mount -t iso9660 -o ro /dev/sr0 /mnt
  - cp /mnt/docker/certs/* /srv/certs
  - cp /mnt/docker/etc/* /srv/etc/
  - umount /mnt
  - docker run -d --name nginx -p ${VM1_EXTERNAL_IP}:${NGINX_PORT}:443 -v /srv/etc/nginx.conf:/etc/nginx/conf.d/default.conf:ro -v /srv/certs:/etc/ssl:ro -v ${NGINX_LOG_DIR}:/var/log/nginx ${NGINX_IMAGE}

userdatavm1

cat $way/config-drives/$VM1_NAME-config/user-data

#user-data vm2
echo ${bold}"user-data $VM2_NAME"${n}
cat << userdatavm2 > $way/config-drives/$VM2_NAME-config/user-data
#cloud-config
ssh_authorized_keys:
  - $(cat  $SSH_PUB_KEY)

apt_update: true
packages:
 - apt-transport-https
 - ca-certificates
 - curl
 - software-properties-common
runcmd:
  - ip link add $VXLAN_IF type vxlan id $VID remote $VM1_INTERNAL_IP local $VM2_INTERNAL_IP dstport 4789
  - ip link set $VXLAN_IF up
  - ip addr add $VM2_VXLAN_IP/24 dev $VXLAN_IF
  - curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
  - add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu xenial stable"
  - apt update
  - apt install -y docker-ce
  - systemctl start docker
  - docker run -d --name apache -p ${VM2_VXLAN_IP}:${APACHE_PORT}:80 ${APACHE_IMAGE}

userdatavm2

cat $way/config-drives/$VM2_NAME-config/user-data

#make ISO
echo ${bold}"Make ISO"${n}
mkdir -p ${way}/config-drives/${VM1_NAME}-config/docker/
cp -r ${way}/docker/* ${way}/config-drives/${VM1_NAME}-config/docker
mkisofs -o $VM1_CONFIG_ISO -V cidata -r -J --quiet $way/config-drives/$VM1_NAME-config
rm -rf ${way}/config-drives/${VM1_NAME}-config/docker/
mkisofs -o $VM2_CONFIG_ISO -V cidata -r -J --quiet $way/config-drives/$VM2_NAME-config

echo ${bold}"Creating VMs"${n}
qemu-img resize $VM1_HDD +2G
virt-install \
  --connect qemu:///system \
  --virt-type=$VM_VIRT_TYPE \
  --name $VM1_NAME \
  --ram $VM1_MB_RAM \
  --vcpus=$VM1_NUM_CPU \
  --$VM_TYPE \
  --os-type=linux --os-variant=ubuntu16.04 \
  --disk path=$VM1_HDD,format=qcow2,bus=virtio,cache=none \
  --disk path=$VM1_CONFIG_ISO,device=cdrom \
  --network network=$EXTERNAL_NET_NAME,mac=$MAC \
  --network network=$INTERNAL_NET_NAME \
  --network network=$MANAGEMENT_NET_NAME \
  --graphics vnc,port=-1 \
  --noautoconsole --quiet --import

echo "sleep 30sec"
sleep 30

qemu-img resize $VM2_HDD +2G
virt-install \
  --connect qemu:///system \
  --virt-type=$VM_VIRT_TYPE \
  --name $VM2_NAME \
  --ram $VM2_MB_RAM \
  --vcpus=$VM2_NUM_CPU \
  --$VM_TYPE \
  --os-type=linux --os-variant=ubuntu16.04 \
  --disk path=$VM2_HDD,format=qcow2,bus=virtio,cache=none \
  --disk path=$VM2_CONFIG_ISO,device=cdrom \
  --network network=$INTERNAL_NET_NAME \
  --network network=$MANAGEMENT_NET_NAME \
  --graphics vnc,port=-1 \
  --noautoconsole --quiet --import


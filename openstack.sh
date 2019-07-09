#!/bin/sh

set -e

PRIVATE_IP=`ip addr show eth0 | grep 'inet ' | awk '{print $2}' | cut -f1 -d'/' | head -n 1 | awk '{print $1}'`
PUBLIC_IP=`curl --silent ident.me --connect-timeout 2 2>/dev/null`
[ -z ${PUBLIC_IP} ] && PUBLIC_IP=${PRIVATE_IP}

MYSQL_USER=root
MYSQL_PASSWORD=password

MQ_USER=openstack
MQ_PASSWORD=password

KS_PASSWORD=password
GLANCE_PASSWORD=password
NOVA_PASSWORD=password
NEUTRON_PASSWORD=password
CINDER_PASSWORD=password

MYSQL_IP=${PRIVATE_IP}
MQ_IP=${PRIVATE_IP}
KS_IP=${PRIVATE_IP}
GLANCE_IP=${PRIVATE_IP}
NOVA_IP=${PRIVATE_IP}
NEUTRON_IP=${PRIVATE_IP}
CINDER_IP=${PRIVATE_IP}

USER_PASSWORD=password
NEUTRON_BR_INT_PORT=eth1
NEUTRON_BR_EX_PORT=eth2

DNS_SERVERS=8.8.8.8

[ -f openstackbootrc ] && . ./openstackbootrc

if [ $USER != root ]; then
    echo 'Please run as root.'
    exit 1
fi

if [ -f /etc/os-release ]; then
    echo 'Ubuntu/Debian ... Proceeding.'
else
    echo 'Require Ubuntu/Debian.'
    exit 1
fi

[ -f .00-upgrade ] || {
echo 'Upgrading'
apt-get update && apt-get -y dist-upgrade
add-apt-repository cloud-archive:liberty
apt-get update && apt-get -y dist-upgrade
echo 'Installing NTP'
apt-get install -y ntp
}
touch .00-upgrade

#Run on MYSQL_IP
[ -f .01-db ] || {
echo 'Setting Password for MySQL'
echo "mysql-server mysql-server/root_password password ${MYSQL_PASSWORD}" | sudo debconf-set-selections
echo "mysql-server mysql-server/root_password_again password ${MYSQL_PASSWORD}" | sudo debconf-set-selections

echo 'Installing MySQL Server'
apt-get install -y mysql-server
apt-get install -y --force-yes python-pymysql

echo 'Setting MySQLD Configuration'
cat > /etc/mysql/conf.d/mysqld_openstack.cnf <<EOF
[mysqld]
bind-address = 0.0.0.0
default-storage-engine = innodb
innodb_file_per_table
collation-server = utf8_general_ci
init-connect = 'SET NAMES utf8'
character-set-server = utf8
EOF
}
touch .01-db

#Run on MQ_IP
[ -f .02-mq ] || {
echo 'Installing RabbitMQ'
apt-get install -y rabbitmq-server

echo 'Setting Password for RabbitMQ'
rabbitmqctl add_user ${MQ_USER} ${MQ_PASSWORD} || echo "User Exists."
rabbitmqctl set_permissions ${MQ_USER} ".*" ".*" ".*"
}
touch .02-mq

#Run on MYSQL_IP
[ -f .03-ospass ] || {
echo 'Setting Password for MySQL Openstack Processes'
{
cat <<EOF
CREATE DATABASE IF NOT EXISTS keystone;
GRANT ALL PRIVILEGES ON keystone.* TO 'keystone'@'%' IDENTIFIED BY 'MYSQL_PASSWORD';
CREATE DATABASE IF NOT EXISTS glance;
GRANT ALL PRIVILEGES ON glance.* TO 'glance'@'%' IDENTIFIED BY 'MYSQL_PASSWORD';
CREATE DATABASE IF NOT EXISTS nova;
GRANT ALL PRIVILEGES ON nova.* TO 'nova'@'%' IDENTIFIED BY 'MYSQL_PASSWORD';
CREATE DATABASE IF NOT EXISTS neutron;
GRANT ALL PRIVILEGES ON neutron.* TO 'neutron'@'%' IDENTIFIED BY 'MYSQL_PASSWORD';
CREATE DATABASE IF NOT EXISTS cinder;
GRANT ALL PRIVILEGES ON cinder.* TO 'cinder'@'%' IDENTIFIED BY 'MYSQL_PASSWORD';
FLUSH PRIVILEGES;
FLUSH TABLES;
EOF
} | sed s/MYSQL_PASSWORD/${MYSQL_PASSWORD}/g | mysql -u${MYSQL_USER} -p${MYSQL_PASSWORD}
}
touch .03-ospass

#Run on All Accordingly.
[ -f .04-ospkg ] || {
echo 'Installing Openstack Clients'
apt-get install --force-yes -y python-openstackclient python-glanceclient python-novaclient python-cinderclient

echo 'Installing Keystone Servers'
apt-get install --force-yes -y keystone apache2 libapache2-mod-wsgi memcached python-memcache

echo 'Installing Glance Servers'
apt-get install --force-yes -y glance

echo 'Installing Nova Servers'
apt-get install --force-yes -y nova-api nova-cert nova-conductor nova-consoleauth nova-scheduler nova-console

echo 'Installing Nova Agents'
apt-get install --force-yes -y nova-compute qemu-kvm sysfsutils nova-novncproxy

echo 'Installing Neutron Servers'
apt-get install --force-yes -y neutron-server neutron-common neutron-dhcp-agent neutron-l3-agent neutron-metadata-agent

echo 'Installing Neutron Agents'
apt-get install neutron-common neutron-plugin-openvswitch-agent openvswitch-switch neutron-plugin-ml2
#neutron-plugin-openvswitch is Deprecated.

echo 'Installing Cinder Servers'
apt-get install --force-yes -y cinder-api cinder-scheduler open-iscsi open-iscsi-utils
#open-iscsi-utils is Deprecated

echo 'Installing Cinder Agents'
apt-get install --force-yes -y cinder-volume lvm2 sysfsutils iscsitarget

echo 'Installing Dashboard'
apt-get install --force-yes -y openstack-dashboard
} 
touch .04-ospkg

#Run on KS_IP
[ -f .05-oskscfg ] || {
echo 'Set up Keystone'
{
cat <<EOF
[DEFAULT]
admin_token = KS_PASSWORD
log_dir = /var/log/keystone
[database]
connection = mysql://keystone:MYSQL_PASSWORD@MYSQL_IP/keystone
[revoke]
driver = sql
[token]
provider = uuid
driver = memcache
EOF
} | sed s/MYSQL_PASSWORD/${MYSQL_PASSWORD}/g | sed s/MYSQL_IP/${MYSQL_IP}/g | sed s/KS_PASSWORD/${KS_PASSWORD}/g > /etc/keystone/keystone.conf
{
cat <<EOF
manual
EOF
} > /etc/init.d/keystone.override
{
cat <<EOF
Listen 5000
Listen 35357
<VirtualHost *:5000>
WSGIDaemonProcess keystone-public processes=5 threads=1 user=keystone group=keystone display-name=%{GROUP}
WSGIProcessGroup keystone-public
WSGIScriptAlias / /usr/bin/keystone-wsgi-public
WSGIApplicationGroup %{GLOBAL}
WSGIPassAuthorization On
<IfVersion >= 2.4>
ErrorLogFormat "%{cu}t %M"
</IfVersion>
ErrorLog /var/log/apache2/keystone.log
CustomLog /var/log/apache2/keystone_access.log combined
<Directory /usr/bin>
<IfVersion >= 2.4>
Require all granted
</IfVersion>
<IfVersion < 2.4>
Order allow,deny
Allow from all
</IfVersion>
</Directory>
</VirtualHost>
<VirtualHost *:35357>
WSGIDaemonProcess keystone-admin processes=5 threads=1 user=keystone group=keystone display-name=%{GROUP}
WSGIProcessGroup keystone-admin
WSGIScriptAlias / /usr/bin/keystone-wsgi-admin
WSGIApplicationGroup %{GLOBAL}
WSGIPassAuthorization On
<IfVersion >= 2.4>
ErrorLogFormat "%{cu}t %M"
</IfVersion>
ErrorLog /var/log/apache2/keystone.log
CustomLog /var/log/apache2/keystone_access.log combined
<Directory /usr/bin>
<IfVersion >= 2.4>
Require all granted
</IfVersion>
<IfVersion < 2.4>
Order allow,deny
Allow from all
</IfVersion>
</Directory>
</VirtualHost>
EOF
} > /etc/apache2/sites-available/001-wsgi-keystone.conf
ln -sf /etc/apache2/sites-available/001-wsgi-keystone.conf /etc/apache2/sites-enabled/001-wsgi-keystone.conf

keystone-manage db_sync
service keystone stop || echo "Unable to stop Keystone."
service apache2 restart

echo 'Set up Keystone Credentials'
export OS_TOKEN=${KS_PASSWORD}
export OS_URL=http://${KS_IP}:35357/v3
export OS_IDENTITY_API_VERSION=3

openstack project create --domain default --description "Openstack Project" admin
openstack project create --domain default --description "Openstack Service" service

openstack user create --domain default --password $USER_PASSWORD admin
openstack role create admin
openstack role add --project admin --user admin admin
openstack service create --name service-keystone --description "Openstack Identity Service" identity

openstack endpoint create --region region-one identity public http://${KS_IP}:5000/v3
openstack endpoint create --region region-one identity internal http://${PRIVATE_IP}:5000/v3
openstack endpoint create --region region-one identity admin http://127.0.0.1:35357/v3

unset OS_TOKEN OS_URL OS_IDENTITY_API_VERSION
}
touch .05-oskscfg

#Run on All Clients
echo 'Set up Openstack Credentials'
[ -f openstackrc ] || {
cat <<EOF
export OS_PROJECT_DOMAIN_ID=default
export OS_USER_DOMAIN_ID=default
export OS_PROJECT_NAME=admin
export OS_TENANT_NAME=admin
export OS_USERNAME=admin
export OS_PASSWORD=USER_PASSWORD
export OS_AUTH_URL=http://KS_IP:35357/v3
export OS_IDENTITY_API_VERSION=3
EOF
} | sed s/USER_PASSWORD/${USER_PASSWORD}/g | sed s/KS_IP/${KS_IP}/g > openstackrc
[ -f openstackrc ] || {
echo "Unable to load Openstack Config."
exit 1
}
. ./openstackrc

#Run on GLANCE_IP
[ -f .06-osglcfg ] || {
echo 'Set up Glance'

echo 'Set up Glance Credentials'
openstack user create --domain default --password ${GLANCE_PASSWORD} glance
openstack role add --project service --user glance admin
openstack service create --name service-glance --description "Openstack Image Service" image

openstack endpoint create --region region-one image public http://${GLANCE_IP}:9292
openstack endpoint create --region region-one image internal http://${PRIVATE_IP}:9292
openstack endpoint create --region region-one image admin http://127.0.0.1:9292

{
cat <<EOF
[DEFAULT]
[database]
connection = mysql://glance:MYSQL_PASSWORD@MYSQL_IP/glance
[keystone_authtoken]
auth_uri = http://KS_IP:5000/v3
auth_url = http://KS_IP:35357/v3
auth_plugin = password
project_domain_id = default
user_domain_id = default
project_name = service
username = glance
password = GLANCE_PASSWORD
[paste_deploy]
flavor = keystone
[glance_store]
default_store = file
filesystem_store_datadir = /var/lib/glance/images/
EOF
} | sed s/MYSQL_PASSWORD/${MYSQL_PASSWORD}/g | sed s/MYSQL_IP/${MYSQL_IP}/g | sed s/GLANCE_PASSWORD/${GLANCE_PASSWORD}/g | sed s/KS_IP/${KS_IP}/g  > /etc/glance/glance-api.conf
{
cat <<EOF
[DEFAULT]
[database]
connection = mysql://glance:MYSQL_PASSWORD@MYSQL_IP/glance
[keystone_authtoken]
auth_uri = http://KS_IP:5000/v3
auth_url = http://KS_IP:35357/v3
auth_plugin = password
project_domain_id = default
user_domain_id = default
project_name = service
username = glance
password = GLANCE_PASSWORD
[paste_deploy]
flavor = keystone
EOF
} | sed s/MYSQL_PASSWORD/${MYSQL_PASSWORD}/g | sed s/MYSQL_IP/${MYSQL_IP}/g | sed s/GLANCE_PASSWORD/${GLANCE_PASSWORD}/g | sed s/KS_IP/${KS_IP}/g > /etc/glance/glance-registry.conf

glance-manage db_sync
service glance-api restart
service glance-registry restart

echo 'Fetching Glance Image'
wget -c http://download.cirros-cloud.net/0.3.4/cirros-0.3.4-x86_64-disk.img -O bootstrap.img

echo 'Uploading Glance Image'
glance image-create --name "cirros" --file bootstrap.img --disk-format qcow2 --container-format bare --visibility public --progress

echo 'Cleaning Glance Image'
rm -f bootstrap.img
}
touch .06-osglcfg

#Run on NOVA_IP
[ -f .07-osnvcfg ] || {
echo 'Set up Nova'
echo 'Set up Nova Credentials'
openstack user create --domain default --password ${NOVA_PASSWORD} nova
openstack role add --project service --user nova admin
openstack service create --name service-nova --description "Openstack Compute Service" compute

openstack endpoint create --region region-one compute public http://${NOVA_IP}:8774/v2/%\(tenant_id\)s
openstack endpoint create --region region-one compute internal http://${PRIVATE_IP}:8774/v2/%\(tenant_id\)s
openstack endpoint create --region region-one compute admin http://127.0.0.1:8774/v2/%\(tenant_id\)s

{
cat <<EOF
[DEFAULT]
dhcpbridge_flagfile=/etc/nova/nova.conf
dhcpbridge=/usr/bin/nova-dhcpbridge
log_dir=/var/log/nova
state_path=/var/lib/nova
lock_path=/var/lock/nova
force_dhcp_release=True
libvirt_use_virtio_for_bridges=True
verbose=True
ec2_private_dns_show_ip=True
api_paste_config=/etc/nova/api-paste.ini
enabled_apis=ec2,osapi_compute,metadata

rpc_backend = rabbit
auth_strategy = keystone
my_ip = PRIVATE_IP
vnc_enabled = True
vncserver_listen = 127.0.0.1
vncserver_proxyclient_address = 127.0.0.1
novncproxy_base_url = http://127.0.0.1:6080/vnc_auto.html

network_api_class = nova.network.neutronv2.api.API
security_group_api = neutron
linuxnet_interface_driver = nova.network.linux_net.LinuxOVSInterfaceDriver
firewall_driver = nova.virt.firewall.NoopFirewallDriver
scheduler_default_filters=AllHostsFilter

[database]
connection = mysql://nova:MYSQL_PASSWORD@MYSQL_IP/nova

[oslo_messaging_rabbit]
rabbit_host = MQ_IP
rabbit_userid = MQ_USER
rabbit_password = MQ_PASSWORD

[keystone_authtoken]
auth_uri = http://KS_IP:5000/v3
auth_url = http://KS_IP:35357/v3
auth_plugin = password
project_domain_id = default
user_domain_id = default
project_name = service
username = nova
password = NOVA_PASSWORD

[glance]
host = PRIVATE_IP

[oslo_concurrency]
lock_path = /var/lock/nova
 
[neutron]
service_metadata_proxy = True
metadata_proxy_shared_secret = openstack
url = http://NEUTRON_IP:9696
auth_strategy = keystone
admin_auth_url = http://KS_IP:35357/v3
admin_tenant_name = service
admin_username = neutron
admin_password = NEUTRON_PASSWORD

[cinder]
os_region_name = region-one
EOF
} | sed s/NEUTRON_PASSWORD/${NEUTRON_PASSWORD}/g | sed s/NOVA_PASSWORD/${NOVA_PASSWORD}/g | sed s/MQ_PASSWORD/${MQ_PASSWORD}/g | sed s/MQ_IP/${MQ_IP}/g | sed s/MQ_USER/${MQ_USER}/g | sed s/MYSQL_PASSWORD/${MYSQL_PASSWORD}/g | sed s/MYSQL_IP/${MYSQL_IP}/g | sed s/KS_IP/${KS_IP}/g | sed s/NEUTRON_IP/${NEUTRON_IP}/g > /etc/nova/nova.conf
{
cat <<EOF
[DEFAULT]
compute_driver=libvirt.LibvirtDriver
[libvirt]
virt_type=qemu
EOF
} > /etc/nova/nova-compute.conf
nova-manage db sync
service nova-api restart
service nova-cert restart
service nova-console restart
service nova-consoleauth restart
service nova-scheduler restart
service nova-conductor restart
service nova-compute restart
service nova-novncproxy restart

#The following requires root.
nova-manage service list 
}
touch .07-osnvcfg

#Run on Neutron Client
[ -f .08-sysctl ] || {
echo 'Setting Sysctl'
cat > /etc/sysctl.d/50-openstack.conf <<EOF 
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
EOF
sysctl -p
service procps restart
}
touch .08-sysctl

#Run on Neutron IP
[ -f .08-osneucfg ] || {
echo 'Set up Neutron Credentials'
echo 'Setting Password for Neutron'
openstack user create --domain default --password ${NEUTRON_PASSWORD} neutron
openstack role add --project service --user neutron admin
openstack service create --name service-neutron --description "Openstack Network Service" network

openstack endpoint create --region region-one network public http://${PRIVATE_IP}:9696
openstack endpoint create --region region-one network internal http://${PRIVATE_IP}:9696
openstack endpoint create --region region-one network admin http://127.0.0.1:9696
echo 'Set up Neutron'
{
cat <<EOF
[DEFAULT]
core_plugin = ml2
service_plugins = router
rpc_backend = rabbit
auth_strategy = keystone
notify_nova_on_port_status_changes = True
notify_nova_on_port_data_changes = True
nova_url = http://NOVA_IP:8774/v2
[agent]
root_helper = sudo /usr/bin/neutron-rootwrap /etc/neutron/rootwrap.conf
[keystone_authtoken]
auth_uri = http://KS_IP:35357/v3
identity_uri = http://KS_IP:5000/v3
auth_plugin = password
project_domain_id = default
user_domain_id = default
project_name = service
username = neutron
password = NEUTRON_PASSWORD
[database]
connection = mysql://neutron:MYSQL_PASSWORD@MYSQL_IP/neutron
[nova]
auth_url = http://KS_IP:35357/v3
auth_plugin = password
project_domain_id = default
user_domain_id = default
region_name = region-one
project_name = service
username = nova
password = NOVA_PASSWORD
[oslo_concurrency]
lock_path = /var/lib/nova/lock
[oslo_messaging_rabbit]
rabbit_host = MQ_IP
rabbit_userid = MQ_USER
rabbit_password = MQ_PASSWORD
EOF
} | sed s/NOVA_IP/${NOVA_IP}/g | sed s/KS_IP/${KS_IP}/g | sed s/NEUTRON_PASSWORD/${NEUTRON_PASSWORD}/g | sed s/MYSQL_PASSWORD/${MYSQL_PASSWORD}/g | sed s/MYSQL_IP/${MYSQL_IP}/g | sed s/NOVA_PASSWORD/${NOVA_PASSWORD}/g | sed s/MQ_IP/${MQ_IP}/g | sed s/MQ_USER/${MQ_USER}/g | sed s/MQ_PASSWORD/${MQ_PASSWORD}/g > /etc/neutron/neutron.conf
{
cat <<EOF
[ml2]
type_drivers=flat,vlan
tenant_network_types=vlan,flat
mechanism_drivers=openvswitch
[ml2_type_flat]
flat_networks=External
[ml2_type_vlan]
network_vlan_ranges=Internal:100:200
[securitygroup]
firewall_driver=neutron.agent.linux.iptables_firewall.OVSHybridIptablesFirewallDriver
enable_security_group=True
[ovs]
bridge_mappings=External:br-ex,Internal:br-int
EOF
} > /etc/neutron/plugins/ml2/ml2_conf.ini
ovs-vsctl add-br br-int || echo "Unable to add-br Internal"
ovs-vsctl add-br br-ex || echo "Unable to add-br External"
ovs-vsctl add-port br-int ${NEUTRON_BR_INT_PORT} || echo "Unable to add-port to Internal"
ovs-vsctl add-port br-ex ${NEUTRON_BR_EX_PORT} || echo "Unable to add-port to External"
BR_EX_ADDRESS=`/sbin/ifconfig ${NEUTRON_BR_EX_PORT} | awk '/inet addr/ {print $2}' | cut -f2 -d ":" `
[ -z "$BR_EX_ADDRESS" ] || {
sed -i "/${NEUTRON_BR_EX_PORT}/,\$d"  /etc/network/interfaces
{
cat << EOF
auto eth2
iface eth2 inet manual
    up ifconfig \$IFACE 0.0.0.0 up
    up ip link set \$IFACE promisc on
    down ip link set \$IFACE promisc off 
    down ifconfig \$IFACE down

# OpenVSwitch Managed
auto br-ex
iface br-ex inet static
    address BR_EX_ADDRESS
    netmask 255.255.255.0
    up ip link set \$IFACE promisc on
    down ip link set \$IFACE promisc off
EOF
} | sed s/BR_EX_ADDRESS/${BR_EX_ADDRESS}/g >> /etc/network/interfaces
}
{
cat <<EOF
[DEFAULT]
auth_uri = http://KS_IP:5000/v3
auth_url = http://KS_IP:35357/v3
auth_region = region-one
auth_plugin = password
project_domain_id = default
user_domain_id = default
project_name = service
username = neutron
password = NEUTRON_PASSWORD
nova_metadata_ip = NOVA_IP
metadata_proxy_shared_secret = openstack
[AGENT]
EOF
} | sed s/KS_IP/${KS_IP}/g | sed s/NOVA_IP/${NOVA_IP}/g | sed s/NEUTRON_PASSWORD/${NEUTRON_PASSWORD}/g > /etc/neutron/metadata_agent.ini
{
cat <<EOF
[DEFAULT]
interface_driver = neutron.agent.linux.interface.OVSInterfaceDriver
dhcp_driver = neutron.agent.linux.dhcp.Dnsmasq
use_namespaces = True
dnsmasq_dns_servers = 8.8.8.8
[AGENT]
EOF
} | sed s/DNS_SERVERS/${DNS_SERVERS}/g > /etc/neutron/dhcp_agent.ini
{
cat <<EOF
[DEFAULT]
interface_driver = neutron.agent.linux.interface.OVSInterfaceDriver
use_namespaces = True
[AGENT]
EOF
} > /etc/neutron/l3_agent.ini
neutron-db-manage --config-file /etc/neutron/neutron.conf --config-file /etc/neutron/plugins/ml2/ml2_conf.ini upgrade liberty
service neutron-server restart
service neutron-plugin-openvswitch-agent restart
service neutron-metadata-agent restart
service neutron-dhcp-agent restart
service neutron-l3-agent restart
neutron agent-list
}
touch .08-osneucfg

#Run on Cinder IP
[ -f .09-oscincfg ] || {
echo 'Set up Cinder Credentials'
echo 'Setting Password for Cinder'
openstack user create --domain default --password ${CINDER_PASSWORD} cinder
openstack role add --project service --user cinder admin
openstack service create --name service-cinder --description "Openstack Block Storage v1 Service" volume
openstack service create --name service-cinderv2 --description "Openstack Block Storage v2 Service" volumev2

openstack endpoint create --region region-one volume public http://${CINDER_IP}:8776/v1/%\(tenant_id\)s
openstack endpoint create --region region-one volume internal http://${PRIVATE_IP}:8776/v1/%\(tenant_id\)s
openstack endpoint create --region region-one volume admin http://127.0.0.1:8776/v1/%\(tenant_id\)s
openstack endpoint create --region region-one volumev2 public http://${CINDER_IP}:8776/v2/%\(tenant_id\)s
openstack endpoint create --region region-one volumev2 internal http://${PRIVATE_IP}:8776/v2/%\(tenant_id\)s
openstack endpoint create --region region-one volumev2 admin http://127.0.0.1:8776/v2/%\(tenant_id\)s
echo 'Set up Cinder'
{
cat <<EOF
[DEFAULT]
rootwrap_config = /etc/cinder/rootwrap.conf
api_paste_confg = /etc/cinder/api-paste.ini
iscsi_helper = tgtadm
volume_name_template = volume-%s
volume_group = cinder-volumes
verbose = True
auth_strategy = keystone
state_path = /var/lib/cinder
lock_path = /var/lock/cinder
volumes_dir = /var/lib/cinder/volumes
rpc_backend = rabbit
auth_strategy = keystone
my_ip = PRIVATE_IP
enabled_backends = lvm
glance_host = GLANCE_IP
[database]
connection = mysql+pymysql://cinder:MYSQL_PASSWORD@MYSQL_IP/cinder
[oslo_messaging_rabbit]
rabbit_host = MQ_IP
rabbit_userid = MQ_USER
rabbit_password = MQ_PASSWORD
[keystone_authtoken]
auth_uri = http://KS_IP:5000/v3
auth_url = http://KS_IP:35357/v3
auth_plugin = password
project_domain_id = default
user_domain_id = default
project_name = service
username = cinder
password = CINDER_PASSWORD
[oslo_concurrency]
lock_path = /var/lib/cinder/tmp
[lvm]
volume_driver = cinder.volume.drivers.lvm.LVMVolumeDriver
volume_group = cinder-volumes
iscsi_protocol = iscsi
iscsi_helper = tgtadm
EOF
} | sed s/GLANCE_IP/${GLANCE_IP}/g | sed s/PRIVATE_IP/${PRIVATE_IP}/g | sed s/KS_IP/${KS_IP}/g | sed s/CINDER_PASSWORD/${CINDER_PASSWORD}/g | sed s/MYSQL_PASSWORD/${MYSQL_PASSWORD}/g | sed s/MYSQL_IP/${MYSQL_IP}/g | sed s/MQ_IP/${MQ_IP}/g | sed s/MQ_USER/${MQ_USER}/g | sed s/MQ_PASSWORD/${MQ_PASSWORD}/g > /etc/cinder/cinder.conf
cinder-manage db sync
pvcreate /dev/sdb
vgcreate cinder-volumes /dev/sdb
service cinder-scheduler restart
service cinder-api restart
service cinder-volume restart
service tgt restart
}
touch .09-oscincfg

[ -f .10-createvm ] || {
echo 'Set up Test VM'
cinder create --display-name myVolume 1
cinder list
neutron subnet-create --name sn1 n1 10.10.10.0/24
neutron net-create en1 --router:external=True --shared --provider:network_type flat --provider:physical_network External
neutron subnet-create --name sen1 --allocation-pool start=192.168.57.100,end=192.168.57.105 en1 192.168.57.0/24
neutron router-create r1
neutron router-gateway-set r1 en1
neutron router-interface-add r1 sn1
neutron security-group-create sg1
neutron security-group-rule-create --protocol icmp sg1
neutron security-group-rule-create --protocol tcp --port-range-min 22 --port-range-max 22 sg1
NET_ID=`nova net-list | awk -v n=4 'n == NR' | cut -d '|' -f 1`
nova boot --flavor m1.tiny --image cirros --security-groups sg1 --nic net-id=${NET_ID} instance100
nova floating-ip-create en1
nova floating-ip-associate --fixed-address 10.10.10.3 instance100 192.168.57.101
}
touch .10-createvm

ssh cirros@192.168.57.101

echo 'Done'
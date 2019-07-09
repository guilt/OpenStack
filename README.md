# OpenStack Build Scripts

Here is where you'll see all the commands for openstack setup....

## Devstack

```bash
sudo apt-get update
sudo apt-get upgrade
sudo shutdown -h now

sudo apt-get install git
git clone https://github.com/openstack-dev/devstack.git -b stable/newton
cd devstack
./stack.sh
```

## The Builders Way

Do everything as a `root`

```bash
sudo ./openstack.sh
```

## Comments

Okay, it isn't perfect, but a way to get started. Send
comments to karthikkumar at gmail dot com
















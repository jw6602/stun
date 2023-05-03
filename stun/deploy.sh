#!/bin/bash

cat "/etc/stun/stun.service" >> "/etc/systemd/system/stun.service"
systemctl start stun.service
systemctl enable stun.service
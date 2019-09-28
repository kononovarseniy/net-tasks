#!/bin/bash

sudo iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A INPUT ! -i lo -p tcp ! --dport 22 -j DROP


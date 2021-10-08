# Ansible

## About

This is a very simple ansible role that installs **geoip-policyd** and **stresstest** on a remote system. It also creates a
system user and group as well as the needed systemd unit file. A default configuration is placed under
**/etc/default/geoip-policyd**. It is a template, which you can modify to suit your needs.

## Note

You need to copy **geoip-policyd** and **stresstest** into the **files/** folder to get this role working correctly.

Make sure, you also have a GeoIP map file on the target host (**/usr/share/GeoIP/GeoLite2-City.mmdb**).

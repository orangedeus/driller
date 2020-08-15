# DRILLER

DNS C2 Testing, for Pihole DNS server and Linux client, integrated with [CALDERA](https://github.com/mitre/caldera).

## Reqs and Dependencies

* Python3
* PyCryptodome
* BeautifulSoup4
* Pihole
* CALDERA

The client server should have its port 53 accept UDP connections, and the DNS server accepting UDP connections in port 1004. Modify at your own will.

## Instructions

With `sudo`:
* Run `python drill.py -W <CALDERA_SERVER_WEBSITE>` on the DNS server with working Pihole installation. A `02-lan.conf` should also be in your `/etc/dnsmasq.d/` folder. (template in config)
* Run `python light.py -D <DNS_SERVER_IP>` on the client.

## Credits

Majority of code is based on [cyberghost](https://github.com/illinoistech-itm/cyberghost) and the default agent Ragdoll of CALDERA.

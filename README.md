# DRILLER

DNS C2 Testing, for Pihole DNS server and Linux client, integrated with [Caldera](https://github.com/mitre/caldera).

## Reqs and Dependencies

* Python3
* PyCryptodome
* BeautifulSoup4
* Pihole
* Caldera

## Instructions
With the Pihole DNS up and running:
* Run `driller.py` on the DNS server
* Run `light.py` on the client

## Credits

Majority of code is based on [cyberghost](https://github.com/illinoistech-itm/cyberghost) and the default agent Ragdoll of Caldera.
Once in a time I needed to get ALL devices in network including fully blocked by firewall.
So I write this.
1. It takes networks list
2. Gets potential routers list.
3. Check that list for accessible SNMP
4. Querying them
5. Fulfill the sqlite table with data

6. As an addition - it can parse vendors list by mac address from wireshark community.

ToDo:

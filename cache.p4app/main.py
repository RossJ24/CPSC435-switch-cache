from p4app import P4Mininet
from mininet.topo import SingleSwitchTopo
import sys
import time

topo = SingleSwitchTopo(2)
net = P4Mininet(program='cache.p4', topo=topo)
net.start()

s1, h1, h2 = net.get('s1'), net.get('h1'), net.get('h2')

# TODO Populate IPv4 forwarding table
table_entries = []
for i in range(1, 2+1):
    table_entries.append(dict(table_name='MyIngress.ipv4_lpm',
                        match_fields={'hdr.ipv4.dstAddr': ["10.0.0.%d" % i, 32]},
                        action_name='MyIngress.ipv4_forward',
                        action_params={'dstAddr': net.get('h%d'%i).intfs[0].MAC(),
                                          'port': i}))
for table_entry in table_entries:
    print(table_entry)
    s1.insertTableEntry(table_entry)
s1.printTableEntries()

data = {i: i+(i *10) for i in range(1,200 + 1)}

# TODO Populate the cache table
print("cache table entries", list(data.keys())[:3])
cache_table_entries  = []
for k in list(data.keys())[:3]:
    cache_table_entries.append(dict(table_name='MyIngress.cache',
                        match_fields={'hdr.req.key': k},
                        action_name='MyIngress.update',
                        action_params={'value': data[k]}))
for table_entry in cache_table_entries:
    print(table_entry)
    s1.insertTableEntry(table_entry)
s1.printTableEntries()
# Now, we can test that everything works

# Start the server with some key-values
server = h1.popen('./server.py %s' % " ".join(["%d=%d" % (k, data[k]) for k in data]), stdout=sys.stdout, stderr=sys.stdout)
time.sleep(0.4) # wait for the server to be listenning

for k in list(data.keys()):
    out = h2.cmd('./client.py 10.0.0.1 %d' % k) # expect a resp from server
    assert out.strip() == ("%d" % data[k])
out = h2.cmd('./other_traffic.py 10.0.0.1') # packet should be dropped
assert out.strip() == "Timeout: not in forwarding table"
out = h2.cmd('./client.py 10.0.0.1 250') # resp not found from server
assert out.strip() == "NOTFOUND"
for k in list(data.keys()):
    out = h2.cmd('./client.py 10.0.0.1 %d' % k) # expect a resp from server
    assert out.strip() == ("%d" % data[k])
out = h2.cmd('./client.py 10.0.0.1 250') # resp not found from server
assert out.strip() == "NOTFOUND"
out = h2.cmd('./other_traffic.py 10.0.0.1') # packet should be dropped
assert out.strip() == "Timeout: not in forwarding table"
server.terminate()

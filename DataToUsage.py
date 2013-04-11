#!/usr/bin/python
#
# Usage: 
#         arpgraph_from_json.py FILE

# JSON Format (that matters, you can ignore the rest)
#{
#    "d" : "00:1e:37:d2:f1:55",                       # Destination MAC
#    "m" : "192.168.168.1 is at 00:13:10:1a:a2:88",   # ARP Message
#    "s" : "00:13:10:1a:a2:88",                       # Source MAC
#    "pk" : 377,                                      # Number of times this happened
#    "te" : 1361939174.023005,                        
#    "tb" : 1361917125.970395,
#}

import sys
import json

# Get the command line arguements
# See http://docs.python.org/2/library/sys.html#sys.argv
# Example usage `./test.py filename.json`
filename = sys.argv[1]  # filename.json

# Open the file given by the command line argument
# See http://docs.python.org/2/library/functions.html#open
data_file = open(filename)

mac_to_number = {}  # { "00:1e:37:d2:f1:55": 0, "00:13:10:1a:a2:88": 1 ... }
new_mac_number = 0
macs_to_count = {}
# Loop through each line in the file.  Each line is a json document.
for line in data_file:
    #print line
    # Parse each json document ( json.loads(line) , I think). This will turn json text into python dictionaries and lists.
    jsondoc = json.loads(line)
    # Get the two addresses
    macto = jsondoc['d']
    macfrom = jsondoc['s']
    # For each IP address, you need to find or make up it's number. What I would do is create a dictionary where the key is the IP address and the value is the number.  For each IP address, get the number from ip_to_number, or, if it's not there, add it yourself.
    # mac_to_number["00:1e:37:d2:f1:55"] = 0
    if not macto in mac_to_number:  
        mac_to_number[macto] = new_mac_number  #  <-- This is the form you want
        new_mac_number += 1
        
    if not macfrom in mac_to_number:
        mac_to_number[macfrom] = new_mac_number        #  <-- this should be like the above, but make sure new_mac_number gets updated!
        new_mac_number = new_mac_number+1
    
    # Generate Key
    linkkey = [macto, macfrom]
    linkkey.sort()
    linkkey = tuple(linkkey)
    
    linkstrength = jsondoc['pk']
    if linkkey in macs_to_count:
        macs_to_count[linkkey] += linkstrength
    else:
        macs_to_count[linkkey] = linkstrength

###
#print mac_to_number
#print macs_to_count

# End the loop.  At the point, link_counts looks like with this:
#   {(0, 1): count_number, (0,2): count_number, (1,2): count_number ...}
#

# Now, using the two dictionaries, generate nodes (from ip_to_number) and links (from link_counts).  Save them to a file. The file should have a structure like arp_graph.
nodes_tup = list(mac_to_number.items())
# http://stackoverflow.com/questions/3121979/how-to-sort-list-tuple-of-lists-tuples
nodes_tup.sort(key=lambda inner: inner[1])

nodes = []
for node in nodes_tup:
    nodes.append({
        "name": node[0]
    })

links = []
for macs, value in macs_to_count.items():
    links.append({
        "source": mac_to_number[macs[0]],
        "target": mac_to_number[macs[1]],
        "value": value
    })
    

print json.dumps({
    "nodes": nodes,
    "links": links
})

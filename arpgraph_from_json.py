#!/usr/bin/python
#
# Usage: 
#         arpgraph_from_json.py FILE

###

# Get the command line arguements

# Open the file given by the command line argument

# ip_to_number = {}
# link_counts = {}
# Loop through each line in the file.  Each line is a json document.

#    Parse each json document ( json.loads(line) , I think). This will turn json text into python dictionaries and lists.

#    Get the two IP addresses

#    For each IP address, you need to find or make up it's number. What I would do is create a dictionary where the key is the IP address and the value is the number.  For each IP address, get the number from ip_to_number, or, if it's not there, add it yourself.

#    Using a tuple of the two IP addresses' numbers as the key to link_counts, count the number of times you see each IP address.


# End the loop.  At the point, link_counts looks like with this:
#   {(0, 1): count_number, (0,2): count_number, (1,2): count_number ...}
#

# Now, using the two dictionaries, generate nodes (from ip_to_number) and links (from link_counts).  Save them to a file. The file should have a structure like arp_graph.



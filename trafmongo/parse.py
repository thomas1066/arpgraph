# parse.py
#
# Contains input validation and parsing

import sys
import re
import socket   #For IP Address Manipulation
import struct   #For IP Address Manipulation
from db_schema import HTTPGetFormat as HGF
from db_schema import PolyProtocolTrafficFiltersFactory, Timeframe

if sys.version_info < (2,6,0):
    import simplejson as json
else:
    import json

# Valid User Parameters
FRAME_START = 'frameStart'
FRAME_END = 'frameEnd'
TIME_PITCH = 'pitch'
FILTERS = 'filters'
GROUP_BY = 'groupBy'
HOST_IP = 'hostip'

class GenericParser(object):
    """
    A few things for extending classes to know about:
        1. self.parsed is a dictionary to place results.
        2. As parameters are handled, each parameter name should go intoi the
           set self.handled.  At the end of the parsing, self.handled is
           checked to make sure that all parameters have been handled.
        3. self.to_parse is the original pyramid request
        4. Remember to _add_step(self.MYSTEP) during __init__.
    """
    def __init__(self):
        self.steps = []
        self.parsed = {}
        self.handled = set()

    def _add_step(self, step):
        self.steps.append(step)

    def parse(self,to_parse):
        """
        Executes all parsing steps against to_parse.
        """
        self.to_parse = to_parse
        for callable in self.steps:
            callable()

        return self.parsed

class TimeframeParserMixin(GenericParser):
    """
    Parses out timeframe.
    """
    def __init__(self):
        super(TimeframeParserMixin, self).__init__()
        self._add_step(self.timeframe_parser)

    def timeframe_parser(self):
        self.handled.add(FRAME_START)
        self.handled.add(FRAME_END)

        # We expect milliseconds and translate to seconds
        try:
            start = int(int(float(self.to_parse.GET[FRAME_START]))/1000)
            end = int(int(float(self.to_parse.GET[FRAME_END]))/1000)

        except KeyError,e:
            raise ValueError("Expected a value for parameter '" + e.message + "'.")
            

        self.parsed['timeframe'] = Timeframe(start,end)

class IPParserMixin(GenericParser):
    """
    Unpacks a string of the form  "192.168.2.3" into parsed[HOST_IP].

    Currently supports IPv4
    """
    def __init__(self):
        super(IPParserMixin,self).__init__()
        self._add_step(self.ip_parser)

    def ip_parser(self):
        self.handled.add(HOST_IP)
        
        try:
            to_parse = self.to_parse.GET[HOST_IP]
        except KeyError:
            raise ValueError("Expected a value for parameter '" + HOST_IP + "'.")

        try:
            # Little bit of stlib magic to turn an ip string into a long.
            ip_int = struct.unpack('<L',socket.inet_aton(to_parse)[::-1])[0]
        except socket.error:
            raise ValueError('Invalid value "' + to_parse + '" for ' + HOST_IP)

        self.parsed['hostip'] = ip_int
        
class TrafficGroupByParserMixin(GenericParser):
    """
    Parses out the 'groupBy' parameter.
    """
    __valid_group_by = set([
        HGF.SOURCE,
        HGF.DEST,
        HGF.CLIENT_PORT,
        HGF.SERVER_PORT
    ])

    __GROUP_BY_RE = re.compile("""["']?[a-zA-Z0-9]+["']?""")

    def __init__(self):
        super(TrafficGroupByParserMixin,self).__init__()
        self._add_step(self.traffic_group_by_parser)

    def traffic_group_by_parser(self):
        self.handled.add(GROUP_BY)

        parsable = self.to_parse.GET[GROUP_BY]

        if self.__GROUP_BY_RE.match(parsable):
            group_by = parsable.strip(""""'""")
        else:
            try:
                group_json = json.loads(self.to_parse.GET[GROUP_BY])
                groupset = set(group_json)
            except:
                raise ValueError("Expected " + GROUP_BY + " as a json list "
                                 + "or alphanumeric string.")

            if len(groupset) < 1:
                raise ValueError("groupBy cannot be empty")

            if not (groupset <= self.__valid_group_by):
                raise ValueError("groupBy cannot contain any of "
                                 + str(groupset - __valid_group_by))

            group_by = groupset

        self.parsed['group_by'] = group_by

class TrafficFiltersParserMixin(GenericParser):
    """
    Parses out the 'filters' parameter using persistence.TrafficFilters
    """
    __CIDR = re.compile("""
        ^                              #Start of String
        [ \t]*                         #Allow extra whitespace
        (?P<ipstr>(?P<oct1>[0-9]{1,3}) #First octet
        [.]                            #Single dot
        (?P<oct2>[0-9]{1,3})           #Second octet
        [.]
        (?P<oct3>[0-9]{1,3})           #Third octet
        [.]
        (?P<oct4>[0-9]{1,3}))          #Forth octet
        ([/](?P<subnet>[0-9]{1,2}))?   #Subnet Bits (optional)
        [ \t]*
        $                              #End of String
    """, re.X)

    __MAC = re.compile("""
        ^                              # Start of String
        [ \t]*                         # Allow extra whitespace
        (                              # Start of the group containing the mac
        [0-9a-fA-F]{2}                 # Two hexadecimal characters
        (:[0-9a-fA-F]{2}){5}           # 5 instances of colon + two hex chars
        )                              # End of the group containing the mac
        [ \t]*                         # Allow extra whitespace
        $                              # End of String
    """, re.X)

    __OTHER_ADDR = re.compile("""
        ^                              # Start of String
        [ \t]*                         # Allow extra whitespace
        (                              # Start of the group containing the mac
        [0-9a-fA-F:]+                  # Some combination of hex and :
        )                              # End of the group containing the mac
        [ \t]*                         # Allow extra whitespace
        $                              # End of String
    """, re.X)

    @classmethod
    def parse_cidr(cls, cidr_match):
        """
        Parses a cidr string
        """

        address = cidr_match.group("ipstr")

        octets = []
        octets.append(int(cidr_match.group("oct1")))
        octets.append(int(cidr_match.group("oct2")))
        octets.append(int(cidr_match.group("oct3")))
        octets.append(int(cidr_match.group("oct4")))

        # Subnet is optional, with a default of 32 (the whole address)
        subnet = cidr_match.group("subnet")
        if subnet is None:
            subnet = 32
        # More validation
        subnet = int(subnet)

        # Validate parsed input
        for o in octets:
            if o > 255 or o < 0:
                raise ValueError("Octets must have values from 0 through 255." 
                                 + " (Not " + str(o) + ")")

        if subnet > 32 or subnet < 0:
            raise ValueError("CIDR masks must have a value from 0 through 32"
                             + " bits. (Not " + str(subnet) + ")")

        # Little bit of stlib magic to turn an ip string into a long.
        mongoip = struct.unpack('<L',socket.inet_aton(address)[::-1])[0]

        # Internal format of an ip address or range is:
        # [32-bit address, netmask length]
        return [mongoip] + [subnet]

    @classmethod
    def parse_mac(cls, mac_match):
        mac = mac_match.group(1) 
        return mac

    @classmethod
    def parse_other_addr(cls, match):
        other = match.group(1) 
        return other

    @classmethod
    def parse_addr(cls, addr):
        """
        Parses an address into either a list (for ip/cidr) or a string (for
        anything else)
        """
        cidr = cls.__CIDR.match(addr)
        if cidr:
            return cls.parse_cidr(cidr)

        mac = cls.__MAC.match(addr)
        if mac:
            return cls.parse_mac(mac)

        other_addr = cls.__OTHER_ADDR.match(addr)
        if other_addr:
            return cls.parse_other_addr(other_addr)

        # If neither cidr or mac, the address must not be valid/supported.
        raise ValueError("Invalid address value: " + addr)

    @staticmethod
    def parse_protocols(protocols):
        """
        Simple validity check based on what PolyProtocolTrafficFilterFactory
        wants to support
        """
        # Must contain something
        if len(protocols) == 0:
            raise ValueError("Must specify at least one protocol")

        # Translate everything to lowercase.
        for i in xrange(0,len(protocols)):
            try:
                protocols[i] = protocols[i].lower()
            except:
                raise ValueError("Protocol cannot be of type " + str(protocols[i].__class__))

        # Ensure that all protocols are supported.
        if not (set(protocols) <= PolyProtocolTrafficFiltersFactory.protocols):
            raise ValueError("Protocols must all be one of " + str(PolyProtocolTrafficFiltersFactory.protocols))
        return protocols
        
    def __init__(self):
        super(TrafficFiltersParserMixin,self).__init__()
        #self._add_step(self.__add_hard_coded_filter)
        self._add_step(self.traffic_filters_parser)

        self.__filters_json = None

        self.__myparsers = {
            HGF.SOURCE: self.parse_addr,
            HGF.DEST: self.parse_addr,
            HGF.CLIENT_PORT: int,
            HGF.SERVER_PORT: int,
            HGF.TRANSPORT: TrafficFiltersParserMixin.parse_protocols,
            HGF.POSITIVE: bool
        }

    def __load_json(self):
        if self.__filters_json is None:
            try:
                self.__filters_json = json.loads(self.to_parse.GET[FILTERS])
            except KeyError:
                raise ValueError("Expected a json list for \"" + FILTERS + "\"")

    def __add_hard_coded_filter(self):
        # XXX: Defunct
        self.__load_json()
        self.__filters_json.append({'positive': False, "proto": ['tcp','udp','icmp'], 'ip1': "192.168.1.112"})

    @staticmethod
    def filter_json_positive(filter_json):
        """
        Utility for use below.
        """
        return filter_json['positive']

    def traffic_filters_parser(self):
        self.handled.add(FILTERS)
        self.__load_json()

        valid_filters_json = []
        found_positive = False
        protocols = set()
        for filter_json in self.__filters_json:
            valid_json = {}

            # Set default protocols (all) if none are specified.
            if HGF.TRANSPORT not in filter_json:
                filter_json[HGF.TRANSPORT] = list(PolyProtocolTrafficFiltersFactory.protocols)

            # Put each parameter through its respective parser
            for param, value in filter_json.iteritems():
                if not param in self.__myparsers:
                    raise ValueError("Filter attribute \"" + param + 
                                     "\" not expected.")

                valid_json[param] = self.__myparsers[param](value)

            # We need at least one positive filter. (and only one?  Maybe..)
            if valid_json['positive'] == True:
                found_positive = True
                protocols.update(valid_json[HGF.TRANSPORT])

            valid_filters_json.append(valid_json)

        # Now that we've validated each filter's json, validate and build the
        # list of filters
        factory = PolyProtocolTrafficFiltersFactory(protocols)
        for valid_json in valid_filters_json:
            # Put the validated json through the filter factory
            factory.create_one(valid_json)

        self.parsed['filters'] = factory.output

class TimePitchParserMixin(GenericParser):
    """
    Parses out the 'pitch' parameter.
    """
    def __init__(self):
        super(TimePitchParserMixin,self).__init__()
        self._add_step(self.time_pitch_parser)

    def time_pitch_parser(self):
        self.handled.add(TIME_PITCH)

        try:
            valid_value = int(int(self.to_parse.GET[TIME_PITCH])/1000)
        except KeyError:
            raise ValueError("Expected parameter \"" + TIME_PITCH + "\".")
        except:
            raise ValueError("Expected \"" + TIME_PITCH + "\" to be an int")

        self.parsed['bucket_size'] = valid_value
        

# The order of classes is important.  Here, TimePitchParserMixin is given a
# "more basic" spot, so that it will execute relevent pieces of code before
# TimeframeParserMixin.  Google python mro for more information.
class TrafficTimeseriesParser(TrafficFiltersParserMixin, TimeframeParserMixin, TimePitchParserMixin):
    """
    A configuration of the GenericParser.
    """

class TrafficTableParser(TrafficFiltersParserMixin, TimePitchParserMixin, TimeframeParserMixin, TrafficGroupByParserMixin):
    """
    A configuration of the GenericParser.
    """

class HostByIPParser(TimeframeParserMixin, IPParserMixin):
    """
    Parser for HostByIP
    """

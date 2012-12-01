# db_schema.py
# Mongo format and related logic lives in here.  Mostly.

# XXX: Python 2.5 Doesn't support @property.setter, so we hack it in for now.
# Squeeze uses python 2.6, which DOES support @property.setter
import sys

if sys.version_info < (2,6,0):
    import __builtin__
    class property(__builtin__.property):
        __metaclass__ = type
            
        def setter(self, method):
            return property(self.fget, method, self.fdel)
            
        def deleter(self, method):
            return property(self.fget, self.fset, method)
            
        @__builtin__.property
        def __doc__(self):
            """Doc seems not to be set correctly when subclassing"""
            return self.fget.__doc__
# End Hack

import math
import re
from collections import defaultdict

class HotDataFormat(object):
    """
    Information and functions for the Hot Data collection format.
    """

    COUNT = 'count'
    CLIENT_IP = 'ip1'
    SOURCE = 's'
    SERVER_IP = 'ip2'
    DEST = 'd'
    CLIENT_PORT = 'p1'
    SERVER_PORT = 'p2'
    PROTOCOL = 'pr'
    TRANSPORT = 'trans'
    TYPE_1 = 'ty1'
    TYPE_2 = 'ty2'
    TRAFFIC = 'b'
    CLIENT_BYTES = 'b1'
    SERVER_BYTES = 'b2'
    CLIENT_FLAGS = 'f1'
    SERVER_FLAGS = 'f2'
    MESSAGE = 'm'
    TIME_BEGIN = 'tb'
    INDX_TIME_BEGIN = 'tbm'
    TIME_END = 'te'
    INDX_TIME_END = 'tem'
    B_TIME_BEGIN = 'sb'
    B_TIME_END = 'se'

    POSITIVE = 'positive'

    # Byte sub-array indexes
    TRAFFIC_OFFSET = 0
    TRAFFIC_CLIENT = 1
    TRAFFIC_SERVER = 2

    # Flag conventions
    SYN = 'S'
    SYNACK = 's'

# END HotDataFormat
HDF = HotDataFormat     # An Alias

class HTTPGetFormat(object):
    """
    Constants for HTTP Get variables
    """

    SOURCE = 's'
    DEST = 'd'
    CLIENT_PORT = 'p1'
    SERVER_PORT = 'p2'
    PROTOCOL = 'pr'
    TRANSPORT = 'trans'
    TYPE_1 = 'ty1'
    TYPE_2 = 'ty2'
    CLIENT_BYTES = 'b1'
    SERVER_BYTES = 'b2'
    CLIENT_FLAGS = 'f1'
    SERVER_FLAGS = 'f2'
    MESSAGE = 'm'
    TIME_BEGIN = 'tb'
    TIME_END = 'te'
    COUNT = 'count'

    POSITIVE = 'positive'
# END HTTPGetFormat
HGF = HTTPGetFormat


class TrafficSegmentABS(object):
    # Data Pitch is the width of a single bucket in timeseries data
    BASE_DATA_PITCH = 1 # Second
    GROUPS_DATA_PITCH = 15 # Seconds
    GROUPS2_DATA_PITCH = 120 # Seconds

    # The width of a document in Groups and groups2.  Used for
    GROUPS_DOC_DURATION = 900 # Seconds
    GROUPS2_DOC_DURATION = 10800 # Seconds

    # TODO: Groups functionality a candidate for abstraction as an instantiable
    # class.

    # AGGREGABLE_FIELDS is, aside from grouping, the set of all aggregatable
    # fields. (For the purposes of returning a table of data.

    # GROUP_TYPES sets some predefined lists of groupings. Expected supported
    # values are "default" and "none"

    # GROUP_INFO_LOST lists attributes that are lost when doing grouping.

    # GROUP_DEFS guides translation from incoming HGF into the segment-
    # specific HDF internal HDF.

    @classmethod
    def translate(cls, groups):
        """
        Uses GROUP_DEFS to translate a set of user-supplied grouping parameters
        into segment specific valid grouping parameters.  Returns a set,
        although the input can conceivably be any iterable of hashables.
        """
        if groups is None:
            return None

        newgroups = set()
        try:
            for field in groups:
                newgroups.add(cls.GROUP_DEFS[field])
        except KeyError as e:
            raise ValueError("group_by: " + e.message + " is not a valid"
                + " grouping parameter")

        return newgroups

class TCPTrafficSegment(TrafficSegmentABS):
    GROUP_TYPES = {
        "default": set((HGF.SOURCE, HGF.DEST, HGF.SERVER_PORT)),
        "none": None
    }
    GROUP_INFO_LOST = set((HGF.CLIENT_PORT,))
    GROUP_DEFS = {
        HGF.SOURCE: HDF.CLIENT_IP,
        HGF.DEST: HDF.SERVER_IP,
        HGF.SERVER_PORT: HDF.SERVER_PORT
    }
    AGGREGABLE_FIELDS = set((HDF.COUNT, HDF.SERVER_BYTES, HDF.CLIENT_BYTES))

    NAME = 'TCP'

    collectionNames = {
        'bytes': 'tcp_sessionBytes',
        'info': 'tcp_sessionInfo',
        'groups': 'tcp_sessionGroups',
        'groups2': 'tcp_sessionGroups2',
        'capture_bytes': 'tcp_captureBytes',
        'capture_info': 'tcp_captureInfo',
        'capture_groups': 'tcp_captureGroups',
        'capture_groups2': 'tcp_captureGroups2'
    }

class UDPTrafficSegment(TrafficSegmentABS):
    GROUP_TYPES = {
        "default": set((HGF.SOURCE, HGF.DEST, HGF.SERVER_PORT)),
        "none": None
    }
    GROUP_INFO_LOST = set((HGF.CLIENT_PORT,))
    GROUP_DEFS = {
        HGF.SOURCE: HDF.CLIENT_IP,
        HGF.DEST: HDF.SERVER_IP,
        HGF.SERVER_PORT: HDF.SERVER_PORT
    }
    AGGREGABLE_FIELDS = set((HDF.COUNT, HDF.SERVER_BYTES, HDF.CLIENT_BYTES, HDF.PROTOCOL))

    NAME = 'UDP'

    collectionNames = {
        'bytes': 'udp_sessionBytes',
        'info': 'udp_sessionInfo',
        'groups': 'udp_sessionGroups',
        'groups2': 'udp_sessionGroups2',
        'capture_bytes': 'udp_captureBytes',
        'capture_info': 'udp_captureInfo',
        'capture_groups': 'udp_captureGroups',
        'capture_groups2': 'udp_captureGroups2'
    }

class ICMPTrafficSegment(TrafficSegmentABS):
    GROUP_TYPES = {
        "default": set((HGF.SOURCE, HGF.DEST, HGF.TYPE_1)),
        "none": None
    }
    GROUP_INFO_LOST = set()  # There's nothing that gets abstracted away
                             # from info to bytes.
    GROUP_DEFS = {
        HGF.SOURCE: HDF.CLIENT_IP,
        HGF.DEST: HDF.SERVER_IP,
        HGF.TYPE_1: HDF.TYPE_1
    }
    AGGREGABLE_FIELDS = set((HDF.COUNT, HDF.SERVER_BYTES, HDF.CLIENT_BYTES))

    NAME = 'ICMP'

    collectionNames = {
        'bytes': 'icmp_sessionBytes',
        'info': 'icmp_sessionInfo',
        'groups': 'icmp_sessionGroups',
        'groups2': 'icmp_sessionGroups2',
        'capture_bytes': 'icmp_captureBytes',
        'capture_info': 'icmp_captureInfo',
        'capture_groups': 'icmp_captureGroups',
        'capture_groups2': 'icmp_captureGroups2'
    }

class OtherTrafficSegment(TrafficSegmentABS):
    GROUP_TYPES = {
        "default": set((HGF.SOURCE,HGF.DEST,HGF.MESSAGE)),
        "none": None
    }
    GROUP_INFO_LOST = set()
    GROUP_DEFS = {
        HGF.SOURCE: HDF.SOURCE,
        HGF.DEST: HDF.DEST,
        HGF.MESSAGE: HDF.MESSAGE
    }
    AGGREGABLE_FIELDS = set((HDF.COUNT, HDF.SERVER_BYTES, HDF.CLIENT_BYTES, HDF.PROTOCOL, HDF.MESSAGE))

    NAME = 'Other'

    collectionNames = {
        'bytes': 'oth_sessionBytes',
        'info': 'oth_sessionInfo',
        'groups': 'oth_sessionGroups',
        'groups2': 'oth_sessionGroups2',
        'capture_bytes': 'oth_captureBytes',
        'capture_info': 'oth_captureInfo',
        'capture_groups': 'oth_captureGroups',
        'capture_groups2': 'oth_captureGroups2'
    }

DB_SEGMENTS = {
    'tcp': TCPTrafficSegment,
    'udp': UDPTrafficSegment,
    'icmp': ICMPTrafficSegment,
    'other': OtherTrafficSegment
}

class MongoJSON(object):
    """
    Class methods for Building mongo query prototypes.
    """

    @classmethod
    def sec_after(cls, queryname, seconds, positive=True):
        """
        Builds an integer number of seconds into a mongo prototype query using
        $gt
        """
        if positive:
            return {queryname: {"$gte": seconds}}
        else:
            return {queryname: {"$not": {'$gte': seconds}}}

    @classmethod
    def sec_before(cls, queryname, seconds, positive=True):
        """
        Builds an integer number of seconds into a mongo prototype query using
        $lt
        """
        if positive:
            return {queryname: {"$lt": seconds}}
        else:
            return {queryname: {"$not": {"$lt": seconds}}}

    @classmethod
    def sec_range(cls, queryname, start, end, positive=True):
        """
        Builds an integer number of seconds into a mongo prototype query using
        $lt
        """
        if positive:
            return {queryname: {"$lt": end, "$gte": start}}
        else:
            return {queryname: {"$not": {"$lt": end, "$gte":start}}}

    @classmethod
    def port(cls, queryname, port, positive=True):
        if positive:
            return {queryname: port}
        else:
            return {queryname: {"$ne": port}}


    @classmethod
    def cidr(cls, queryname, ipaddr, positive=True):
        mongoip = ipaddr[0]
        subnet = ipaddr[1]

        netmask = ~(2 ** (32 - subnet) - 1)

        subnetStart = mongoip & netmask
        subnetEnd = subnetStart + (~netmask)

        # Build mongo query
        if positive:
            mongo_query = {queryname: {"$gte": subnetStart, "$lte": subnetEnd}}
        else:
            # Backwards with $or is like negation here
            mongo_query = {"$or": [{queryname: {"$gt": subnetEnd}},
                                   {queryname: {"$lt": subnetStart}}]}

        return mongo_query

    @classmethod
    def pr(cls, queryname, pr, positive=True):
        if positive:
            return {queryname: pr}
        else:
            return {queryname: {"$ne": pr}}

    @classmethod
    def regex(cls, queryname, expr, positive=True):
        #XXX: Figure out if there are injection attacks for this.
        queryre = re.compile(expr)
        if positive:
            return {queryname: queryre}
        else:
            return {queryname: {"$not": queryre}}

    @classmethod
    def text(cls, queryname, expr, positive=True):
        if positive:
            return {queryname: expr}
        else:
            return {queryname: {"$not": expr}}

class TrafficFilterABS(object):
    """
    Scaffolding around the 'options' concept
    """
    def __init__(self, json):
        self.positive = True # Init.
        for name, value in json.iteritems():
            setattr(self, name, value)

    def is_empty(self):
        """
        If true indicates an empty filter. (Which is a filter to select all
        traffic for that type of filter)
        """
        raise NotImplimentedError

    def to_match_doc(self):
        """
        Returns a dictionary suitable for use in a mongo find() or $match.
        """
        raise NotImplimentedError

class IPTrafficFilter(TrafficFilterABS):
    """
    Used to generate match documents for mongodb
    """
    @staticmethod
    def check_ip(ip):
        if not isinstance(ip,list):
            ip = [ip,32] # IPv4

        if ip[0] >= 2**32:
            raise ValueError("IPv4 Addresses must be less than 2^32.")
        elif ip[0] < 0:
            raise ValueError("IPv4 Addresses cannot be negative.")
        elif not 0 <= ip[1] <= 32:
            raise ValueError("Subnets must be from 0 to 32 bits")

        return ip

    def __init__(self, json):
        self._s = None
        self._d = None
        super(IPTrafficFilter, self).__init__(json)

    def is_empty(self):
        if self.s is not None or self.d is not None:
            return False
        return True

    def to_match_doc(self):
        pson = {}
        if self.s is not None:
            pson.update(MongoJSON.cidr(HotDataFormat.CLIENT_IP, self.s, self.positive))
            
        if self.d is not None:
            pson.update(MongoJSON.cidr(HotDataFormat.SERVER_IP, self.d, self.positive))
            
        return pson
            
    @property
    def s(self):
        return self._s

    @s.setter
    def s(self,ip):
        self._s = self.check_ip(ip)

    @property
    def d(self):
        return self._d

    @d.setter
    def d(self,ip):
        self._d = self.check_ip(ip)

class UDPTrafficFilter(IPTrafficFilter):
    """
    Supports IP Addresses and Ports
    """

    TYPE = UDPTrafficSegment

    @staticmethod
    def check_p(p):
        if p >= 2**16:
            raise ValueError("Port numbers must be less than 2^32.")
        elif p < 0:
            raise ValueError("Port numbers cannot be negative.")

        return p

    def __init__(self, json):
        self._p1 = None
        self._p2 = None
        super(UDPTrafficFilter,self).__init__(json)

    def is_empty(self):
        # If a superclass says we're not empty, we're not empty. Otherwise
        # check the attributes we know about.
        so_far = super(UDPTrafficFilter,self).is_empty()
        if (not so_far) or (self.p1 is not None) or (self.p2 is not None):
            return False
        return True

    def to_match_doc(self):
        pson = super(UDPTrafficFilter,self).to_match_doc()
        if self.p1 is not None:
            pson.update(MongoJSON.port(HotDataFormat.CLIENT_PORT, self.p1, self.positive))
            
        if self.p2 is not None:
            pson.update(MongoJSON.port(HotDataFormat.SERVER_PORT, self.p2, self.positive))

        return pson

    @property
    def p1(self):
        return self._p1

    @p1.setter
    def p1(self,p):
        self.check_p(p)
        self._p1 = p

    @property
    def p2(self):
        return self._p2

    @p2.setter
    def p2(self,p):
        self.check_p(p)
        self._p2 = p

class TCPTrafficFilter(UDPTrafficFilter):
    TYPE = TCPTrafficSegment
    # Otherwise Identical to UDP TrafficFilter

class ICMPTrafficFilter(IPTrafficFilter):
    """
    Supports IP Addresses and the "Type 1" field
    """

    TYPE = ICMPTrafficSegment

    TY_RE = re.compile("""
        [0-9]{1,2}      # First Number
        (
            [.]         # Period
            [0-9]{1,2}  # Second Number
        )?              # This group is optional.
    """,re.X)

    @staticmethod
    def check_ty(type):
        if not self.TY_RE.match(type):
            raise ValueError('ICMP Type Fields should be two one-or-two digit numbers seperated by a period.  As in: "8.0" (Echo Request)')
        return type

    def __init__(self, json):
        self._ty1 = None
        super(ICMPTrafficFilter,self).__init__(json)

    def is_empty(self):
        # If a superclass says we're not empty, we're not empty. Otherwise
        # check the attributes we know about.
        so_far = super(ICMPTrafficFilter,self).is_empty()
        if (not so_far) or (self.ty1 is not None):
            return False
        return True

    def to_match_doc(self):
        pson = super(ICMPTrafficFilter,self).to_match_doc()
        if self.ty1 is not None:
            pson.update(MongoJSON.port(HotDataFormat.TYPE_1, self.ty1, self.positive))
        return pson

    @property
    def ty1(self):
        return self._ty1

    @ty1.setter
    def ty1(self,type):
        self.check_ty(type)
        self._ty1 = type

class OtherTrafficFilter(TrafficFilterABS):
    TYPE = OtherTrafficSegment

    ADDR_RE = re.compile("""
        [0-9a-fA-F.*:]*     #Just a collection of numbers and punctuation.
    """, re.X)

    @classmethod
    def check_pr(cls, match):
        return match

    @classmethod
    def check_addr(cls, addr):
        if not cls.ADDR_RE.match(addr):
            raise ValueError('When querying for Other types of traffic, only hexadecimal, decimal, periods and colons, as well as the wildcard "*" are allowed.')
        return addr

    def __init__(self, json):
        self._m = None
        self._s = None
        self._d = None
        super(OtherTrafficFilter,self).__init__(json)

    def is_empty(self):
        if (self.m is not None) or (self.s is not None) or (self.d is not None):
            return False
        return True

    def to_match_doc(self):
        pson = {}
        if self.m is not None:
            pson.update(MongoJSON.pr(HotDataFormat.PROTOCOL, self.m, self.positive))
        if self.s is not None:
            pson.update(MongoJSON.text(HotDataFormat.SOURCE, self.s, self.positive))
        if self.d is not None:
            pson.update(MongoJSON.text(HotDataFormat.DEST, self.d, self.positive))

        return pson

    @property
    def s(self):
        return self._s

    @s.setter
    def s(self, s):
        self.check_addr(s)
        self._s = s
        
    @property
    def d(self):
        return self._d

    @d.setter
    def d(self, d):
        self.check_addr(d)
        self._d = d
        
    @property
    def m(self):
        return self._m

    @m.setter
    def m(self, m):
        self.check_pr(m)
        self._m = m

# XXX: Circular Reference between TrafficFilter and TrafficSegment
TCPTrafficSegment.FILTER = TCPTrafficFilter
UDPTrafficSegment.FILTER = UDPTrafficFilter
ICMPTrafficSegment.FILTER = ICMPTrafficFilter
OtherTrafficSegment.FILTER = OtherTrafficFilter

class TrafficFilterList(list):
    """
    Extention of the builtin 'list' for Traffic Filters. Some of the attribute
    passthroughs work on the assumption that all filters are of the same type.
    """
    def contains_param(self,param):
        """
        Tests if this collection of filters contains the given parameter.

        Ex: bunch_of_filters.contains_param('p2')
        """
        contains = False
        for filter in self:
            if getattr(filter, param, None) is not None:
                contains = True
                break

        return contains

    def is_empty(self):
        answer = True
        for filter in self:
            if not filter.is_empty():
                answer = False
                break
        return answer

    def to_match_doc(self):
        ands = []

        # We treat the first positive filter differently, putting it first.
        placed_first = False
        for filter in self:
            json = filter.to_match_doc()
            if placed_first or not filter.positive:
                ands.append(json)
            else:
                placed_first = True
                ands.insert(0, json)
            
        return {"$and": ands}
                
    @property
    def TYPE(self):
        return self[0].TYPE

class PolyProtocolTrafficFiltersFactory(object):
    """
    Methods for creating filters.
    """
    protocols = set(DB_SEGMENTS.keys())

    def __init__(self, valid_proto=protocols):
        self.valid_proto = set(valid_proto)
        self.output = defaultdict(TrafficFilterList)

    def create_many(self, valid_json):
        """
        Creates 1 or more filters from validated and pre-parsed user input.
        Takes a list of valid filter jsons.

        All generated filters make their way to self.output
        """
        for filter_json in valid_json:
            self.create_one(filter_json)
                
        return self.output
        
    def create_one(self, valid_json):
        """
        Creates 1 or more filters from validated and pre-parsed user input.
        Takes a *single* valid filter json.

        All generated filters make their way to self.output
        """
        # Note that we pop out the protocol filter here, so not to confuse
        # the individual filter constructors.
        proto_to_create = valid_json.pop(HotDataFormat.TRANSPORT)
        for proto in proto_to_create:
            proto = proto.lower()

            # Check to ensure we're configured to use this protocol. If we're
            # not, just ignore it and carry on.
            if proto not in self.valid_proto:
                continue

            # Do the actual production, just passing on the json
            db_segment = DB_SEGMENTS[proto]
            FilterClass = db_segment.FILTER
            filter = FilterClass(valid_json)

            # Put the new filter into the structure. We use defaultdict, adding
            # TrafficFilterLists only as we need them, avoiding empty lists
            # which would imply a broad filter.
            self.output[db_segment].append(filter)

class Timeframe(object):
    """
    The combination of a start and end time.  A similar concept to python's
    timedelta, but with absolute endpoints. All times are integer seconds, and
    all durations are expected to be > 0. Contains logic for going to a mongo match query.
    """
    @staticmethod
    def parse_time(time):
        val = int(time)
        if val < 0:
            raise ValueError("Times are expected to be after the Epoch")
        return val

    def __init__(self, start, end):
        """
        Creates a new time range with a start time and end time.
        """
        self._start = self.parse_time(start)
        self._end = self.parse_time(math.ceil(end))
        if self.duration < 1:
            raise ValueError("Timeframes are expected to start before they end.")

    @property
    def start(self):
        return self._start

    @property
    def end(self):
        return self._end

    @property
    def duration(self):
        return self._end - self._start

class InfoTimeframe(Timeframe):
    def to_match_doc(self):
        pson = {}
        pson.update(MongoJSON.sec_before(HotDataFormat.TIME_BEGIN, self.end))
        pson.update(MongoJSON.sec_after(HotDataFormat.TIME_END, self.start))
        pson.update(MongoJSON.sec_before(HotDataFormat.INDX_TIME_BEGIN, self.end + 59))
        pson.update(MongoJSON.sec_after(HotDataFormat.INDX_TIME_END, self.start - 59))

        return pson

class BytesTimeframe(Timeframe):
    def to_match_doc(self):
        pson = {}
        pson.update(MongoJSON.sec_after(HotDataFormat.B_TIME_END, self.start))
        pson.update(MongoJSON.sec_before(HotDataFormat.B_TIME_BEGIN, self.end))
        
        return pson

class GroupsTimeframe(Timeframe):
    SECONDS_PER_DOC = 15 * 60
    def to_match_doc(self):
        # Groups are delimited at 15 minute intervals.  Therefore, since we're
        # look only at INDX_TIME_BEGIN, we need to kick out the start time to
        # include the 15 minute interval that contains the start time.
        start = self.start - (self.start % self.SECONDS_PER_DOC)
        return MongoJSON.sec_range(HotDataFormat.INDX_TIME_BEGIN, start, self.end)

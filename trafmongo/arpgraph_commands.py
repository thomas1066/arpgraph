### arpgraph_commands.py ###
#
# Here, a command indicates a single action that might be taken.  An action
# might be to read a certain kind of data from the database.  An action might
# be to perform some sort of CRUD opporation on a persisted object.
#
# Commands are understood to have a working knowlege of whatever backend their
# working with. (Mongo, geoip, etc) and the different general schema that are
# being used.
#
# Commands are currently broken up into 2 areas:
#   1. Commands
#
#   2. Command Factories
#       Command Factories contain the logic to construct various commands,
#       simplifying the logic of client code.  Think of them as a replacement
#       for overly large and complex __init__ functions.
#
###

import sys
from trafmongo.commands import CommandFactoryABS, MongoQueryCommandABS

# XXX: Python 2.5 Doesn't support @property.setter, so we hack it in for now.
# Squeeze uses python 2.6, which DOES support @property.setter

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

class ARPGraphCommand(MongoQueryCommandABS):
    def execute(self):
        """
        This is where the bulk of your code should go, until we start worrying
        about options.

        Here, self.db is defined as a pymongo database:
        http://api.mongodb.org/python/current/api/pymongo/database.html
        """

        # Do stuff here
        # self.db["my_collection_name"].find(blah blah)

        self.annotated_results = {"put_something": "here"}
        # Debug infor can go in this dictionary if you ever want.
        self.debug_info = {"nothing": "here_yet"} 

class ARPGraphCommandFactory(CommandFactoryABS):
    """
    Creates an ARPGraphCommand.  No intelligence.
    """

    def __init__(self, options):
        self._options = options

    def create_command(self):
        return ARPGraphCommand(options)


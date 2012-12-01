### commands.py ###
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

class CommandInterface(object):
    """
    A command.
    """
    def __init__(self):
        self.debug_info = {}

    def execute(self):
        raise NotImplementedError

class ConfigurableCommandABS(CommandInterface):
    """
    Root of all KnightWatch Mongo Queries.  Using mixins and such, this could
    be fairly extensible.
    """
    def __init__(self, options):
        super(ConfigurableCommandABS,self).__init__()
        self.options(options)

    def options(self, options):
        """
        Takes a dictionary of options and attempts to apply them to this query.
        """
        for name, value in options.iteritems():
            # "self.OPTIONNAME = OPTIONVALUE"
            setattr(self, name, value)

    def execute(self):
        raise NotImplementedError

class MongoQueryCommandABS(ConfigurableCommandABS):
    @property
    def db(self):
        return self._db

    @db.setter
    def db(self, db):
        self._db = db

###
# Command Factories
#
# Command factories take a lot of the decision-making and complexity out of
# both the client code and the commands themselves, letting them focus on what
# they're good at instead.
class CommandFactoryABS(object):
    """
    Abstract Base Class for a command factory.
    """
    def __init__(self, options):
        self._options = options

    def create_command(self):
        """
        Returns something that impliments CommandInterface
        """
        raise NotImplementedError

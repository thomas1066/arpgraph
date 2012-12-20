from pyramid.view import view_config
from trafmongo import resources 
#from trafmongo.parse import TrafficTimeseriesParser, TrafficTableParser, HostByIPParser
from trafmongo.db_schema import Timeframe, HotDataFormat
from trafmongo.arpgraph_commands import ARPGraphCommandFactory

#XXX: These were to be classes, but Python 2.5 doesn't support class decorators
#class PyramidView(object):
#    def __init__(context, request):
#        self.context = context
#        self.request = request
#
#    def __call__(self):
#        return NotImplementedError

@view_config(name='', renderer='json', context=resources.ARPGraphData)
def ARPGraphView(context, request):
    #parser = TrafficTimeseriesParser()
    #subfactory = InOutTimeseriesCommandFactory

    # Parse user input
    #options = parser.parse(request)
    options = request.GET
    #options['db'] = context.db

    # Build and run command
    factory = ARPGraphCommandFactory(options)
    command = factory.create_command()
    command.execute()

    results = {
        "data": command.annotated_results,
        "debug": command.debug_info,
        "request": dict(request.GET)
    }

    return results

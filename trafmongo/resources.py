###
# resources.py
#
# Pyramid resources.  Act something like dictionaries.
class BaseResource(object):
    """
    The Base Resource Class.  Ensures that everyone is on the same page.
    """

    subresources = {}

    def __init__(self, request):
        self.request = request
        self.db = request.db

    def __getitem__(self, nextpath):
        return self.subresources[nextpath](self.request)

class ARPGraphData(BaseResource):
    """
    /api/arpgraph
    """

class API(BaseResource):
    """
    Ajax API. (Not really REST)
    /api
    """
    subresources = {"arpgraph": ARPGraphData}

class ARPViz(BaseResource):
    """
    /arpviz
    """

class Root(BaseResource):
    """
    The root of the app, '/'
    """
    subresources = {"api": API,
                    "arpviz": ARPViz}

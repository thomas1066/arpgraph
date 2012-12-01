from pyramid.config import Configurator
from pyramid.events import subscriber
from pyramid.events import NewRequest
from trafmongo.resources import Root
import pymongo
from ConfigParser import SafeConfigParser

def main(global_config, **settings):
    """
    This function returns a Pyramid WSGI application.
    """

    # Modified from the pyramid cookbook
    # Generate persistence objects
    db_uri = kw_config.get('mongo','mongo_server')
    db_port = kw_config.getint('mongo','mongo_port')
    db_name = kw_config.get('mongo','traffic_db')
    conn = pymongo.Connection(db_uri, db_port)
    db = conn[db_name]

    # Store persistence objects for use during requests
    settings['db_conn'] = conn
    settings['db'] = db

    config = Configurator(root_factory=Root, settings=settings)
    config.add_static_view('static', 'trafmongo:static')

    # This subscriber will make it easier to access the database objects
    config.add_subscriber(add_mongo_db, NewRequest)

    # Find views
    config.scan('trafmongo')

    return config.make_wsgi_app()


def add_mongo_db(event):
    """
    Creates a few "shortcuts" for the db objects
    """
    settings = event.request.registry.settings
    event.request.db = settings['db']

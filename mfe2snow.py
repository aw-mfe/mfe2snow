#!/usr/bin/env python3

from configparser import NoOptionError
from configparser import SafeConfigParser
import argparse
import base64
import ipaddress
import json
import logging
import logging.config
import os
import socket
import sys
import time
import requests
requests.packages.urllib3.disable_warnings()

""" McAfee ESM <=> ServiceNow

This script can be called as an alarm action on the McAfee ESM to send data
to ServiceNow via the API to create tickets. Optionally, ticket data is 
transmitted back to the ESM via syslog and referenced as an event. The event
allows for contextual linking directly to the ticket from the ESM.

The script requires Python 3 and was tested with 3.5.2 for Windows and Linux.

Other modules, requests and configparser, are also required.
See requirements.txt.

The script requires two files - in the same directory by default:
 - config.ini
 - logging.conf

 The files are available at:
https://raw.githubusercontent.com/andywalden/mfe2snow/master/logging.conf
https://raw.githubusercontent.com/andywalden/mfe2snow/master/config.ini

The config.ini must be updated with the hostname and credentials to
access ServiceNow. If syslog feedback is used then the Receiver host
needs to be set as well.

The logging.conf does not need to be modified, but it is possible to
adjust the logging level and format of the output with this file.

Example:

    $ python mfe2snow.py 
    
    The output is also written to a file that is overwritten each time
    the script is run. The filename is .mfe2snow.log

Make sure the permissions on the config.ini file are secure as not to
expose any credentials.
"""

__author__ = "Andy Walden"
__version__ = "1.0"

class Args(object):

    def __init__(self, args):
        self.log_levels = ["quiet", "error", "warning", "info", "debug"]
        self.formatter_class = argparse.RawDescriptionHelpFormatter
        self.parser = argparse.ArgumentParser(
                formatter_class=self.formatter_class,
                description="Send McAfee ESM Alarm data to ServiceNow"
            )
        self.args = args

        self.parser.add_argument("-v", "--version",
                                 action="version",
                                 help="Show version",
                                 version="%(prog)s {}".format(__version__))

        self.parser.add_argument("-l", "--level",
                                 default=None, dest="level",
                                 choices=self.log_levels, metavar='',
                                 help="Logging output level. Default: warning")
        
        self.parser.add_argument("-c", "--config",
                                 default=None, dest="cfgfile", metavar='',
                                 help="Path to config file. Default: config.ini")

        self.parser.add_argument("fields", nargs='*', metavar='',
                                 help="Key=Values for the query")

        self.pargs = self.parser.parse_args()

    def get_args(self):
        return self.pargs

        
class Syslog(object):
    """Open TCP socket using supplied server IP and port. 
       
    Returns socket or None on failure
    """

    def __init__(self, 
                server, 
                port=514):
        logging.debug("Function: open_socket: %s: %s", server, port)
        self.server = server
        self.port = int(port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.connect((self.server, self.port))

    def send(self, data):
        """ 
        Sends data to the established connection
        """
        
        self.data = data
        self.sock.sendall(data.encode())
        logging.info("Syslog feedback sent")

class SNOW(object):
    """ Send to ServiceNow API 
    
    Initialize with host, user and passwd to create connection.
    
    post() sends JSON query to SNOW.
    
    """

    def __init__(self, host, user, passwd):
            self.host = host
            self.user = user
            self.passwd = passwd
            self.url = "https://" + host

            self.auth_string = '{}'.format(base64.b64encode('{}:{}'
                                   .format(user,passwd)
                                   .encode('utf-8'))
                                   .decode('ascii'))

            self.headers = {'Authorization':'Basic '+ self.auth_string, 'Content-Type': 'application/json'}


    def send(self, query_conf, uri_string):
        """ Takes API query (usually JSON string) and the
            part of the URI that is after the hostname.
            Runs query and returns result object. """

        self.query_conf = query_conf
        self.uri_string = uri_string
        result = requests.post(self.url + self.uri_string,
                               headers=self.headers,
                               data=query_conf, verify=False)

        return result

class Query(object):

    def __init__(self):
        self.qconf = []

    def create(self, **kwargs):
        self.query_dict = kwargs
        self.alarm = self.query_dict.pop('alarm', 'McAfee ESM Alarm')
        self.node = self.query_dict.get('source-ip', '0.0.0.0')
        
        self.info = ", ".join(["=".join([key, str(val)]) 
                              for key, val in self.query_dict.items()])
        
        self.qconf = {
            "active" : "false",
            "classification" : "1",
            "description" : self.alarm,
            "source" : "McAfee ESM",
            "node" : self.node,
            "type" : "ESM" ,
            "message_key" : "abc123",
            "additional_info" : self.info,
            "severity" : "7",
            "state" : "Ready",
            "sys_class_name" : "em_event",
            "sys_created_by" : "mcafee.integration"
            }

        return(json.dumps(self.qconf))

        
def main():
    """ Main function """
  
    # Process any command line args
    args = Args(sys.argv)
    pargs = args.get_args()
    fields = dict(x.split('=', 1) for x in pargs.fields)
    # Read in logging file
    logging.config.fileConfig("logging.conf")
    # Look for logging override
    if pargs.level:
        logger = logging.getLogger()
        logger.setLevel(getattr(logging, pargs.level.upper()))
    
    # Read in config file 
    if pargs.cfgfile:
        configfile = pargs.cfgfile
    else:
        configfile = 'config.ini'
    
    if os.path.isfile(configfile):
        logging.debug("Config file detected: %s", configfile)
        confparse = SafeConfigParser()
        confparse.read(configfile)
        config = confparse['DEFAULT']
        host = config['snowhost']
        user = config['snowuser']
        passwd = config['snowpass']
    else:
        logging.error("Config file not found: %s", pargs.cfgfile)
        sys.exit()
   
    # Create ServiceNow connection
    snowhost = SNOW(host, user, passwd)
    
    new_ticket = Query()
    new_ticket_q = new_ticket.create(**fields)
    result = snowhost.send(new_ticket_q, '/api/now/table/em_event')

    try:
        syslog_host = config.get('sysloghost')
        syslog_port = config.get('syslogport')
        syslog = Syslog(syslog_host, syslog_port)

        syslog.send(result.text)
    except NoOptionError:
        logging.debug("Syslog feedback disabled. Settings not detected.")
        
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.warning("Control-C Pressed, stopping...")
        sys.exit()
        

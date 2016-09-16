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
https://raw.githubusercontent.com/andywalden/mf22snow/config.ini
 
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
__version__ = "1.1a"
 
class Args(object):
    """
    Handles any args and passes them back as a dict
    """
 
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
 
                                 help="Key=Values for the query. Example: \n  \
                                 alarm=\"The milk has spilled\" sourceip=\"1.1.1.1\", destip=\"2.2.2.2\"")
 
        self.pargs = self.parser.parse_args()
 
    def get_args(self):
        return self.pargs
 
 
class Syslog(object):
    """
    Open TCP socket using supplied server IP and port.
 
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
    """
    Send to ServiceNow API
    Initialize with host, user and passwd to create connection.
    send() sends JSON query to SNOW.
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
        """
        Sends URI method and JSON query string
        Runs query and returns result object.
        """
 
        self.query_conf = query_conf
        self.uri_string = uri_string
        result = requests.post(self.url + self.uri_string,
                               headers=self.headers,
                               data=query_conf, verify=False)
 
        return result
 
class Query(object):
    """
    Returns JSON query from provided dict
    """
 
    def __init__(self):
        self.qconf = []
 
    def create(self, **kwargs):
        self.query_dict = kwargs
        self.alarm = self.query_dict.pop('alarm', 'McAfee ESM Alarm')
        self.node = self.query_dict.pop('node', '0.0.0.0')
        self.severity = self.query_dict.pop('severity', '25')
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
            "severity" : self.severity,
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
    try:
        fields = dict(x.split('=', 1) for x in pargs.fields)
    except ValueError:
        logging.error("Invalid input. Format is field=value")
        sys.exit(1)
    # Read in logging file
    logging.config.fileConfig("logging.conf")
    # Look for logging override
    if pargs.level:
        logger = logging.getLogger()
        logger.setLevel(getattr(logging, pargs.level.upper()))
 
    # Read in config file
    configfile = pargs.cfgfile if pargs.cfgfile else 'config.ini'
    if os.path.isfile(configfile):
        logging.debug("Config file detected: %s", configfile)
        confparse = SafeConfigParser()
        confparse.read(configfile)
        c = confparse['DEFAULT']
        host = c['snowhost']
        user = c['snowuser']
        passwd = c['snowpass']
        homenet = [c['homenet']]
    else:
        logging.error("Config file not found: %s", pargs.cfgfile)
        sys.exit()
 
    # Check for IPs in arguments
    destip = fields.get('destip', None)
    sourceip = fields.get('sourceip', None)
 
    # Figure out which IP should be 'node'
    if sourceip:
        for subnet in homenet:
            if ipaddress.ip_address(sourceip) in ipaddress.ip_network(subnet):
                fields['node'] = sourceip
            elif ipaddress.ip_address(destip) in ipaddress.ip_network(subnet):
                fields['node'] = destip
            else:
                fields['node'] = sourceip
 
    # Check for severity in arguments. Map ESM severity (1-100) to SNOW (1-5)
    s = int(fields.get('severity', 25))
    if 90 <= s <= 100:  fields['severity'] = 1 # Critical
    if 75 <= s <= 89:  fields['severity'] = 2# Major
    if 65 <= s <= 74:   fields['severity'] = 3 # Minor
    if 50 <= s <= 64:  fields['severity'] = 4 # Warning
    if 0 <= s <= 49: fields['severity'] = 5   # Info
 
    # Create ServiceNow connection
    snowhost = SNOW(c['snowhost'], user, passwd)
 
    # New ticket query
    new_ticket = Query()
    new_ticket_q = new_ticket.create(**fields)
    #result = snowhost.send(new_ticket_q, '/api/now/table/em_event')
    print(new_ticket_q)
 
    # Syslog feedback to ESM
    try:
        syslog_host = c.get('sysloghost')
        syslog_port = c.get('syslogport')
        #syslog = Syslog(syslog_host, syslog_port)
 
        #syslog.send(result.text)
    except NoOptionError:
        logging.debug("Syslog feedback disabled. Settings not detected.")
 
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.warning("Control-C Pressed, stopping...")
        sys.exit()

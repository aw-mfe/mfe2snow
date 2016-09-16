# mfe2snow
Open ServiceNow tickets from McAfee ESM

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
 
Example files are available at:
https://raw.githubusercontent.com/andywalden/mfe2snow
 
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

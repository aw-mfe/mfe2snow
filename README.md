This script can be called as an alarm action on the McAfee ESM to send data
to ServiceNow via the API to create tickets. Optionally, ticket data is
transmitted back to the ESM via syslog and referenced as an event. The event
allows for contextual linking directly to the ticket from the ESM.

The script requires Python 3 and was tested with 3.5.2 for Windows and Linux.
Other modules, requests and configparser, are also required.

The script requires a config.ini file for the credentials. The filename and
path can be set from the command line.

An example config.ini is available at:

https://raw.githubusercontent.com/andywalden/mfe2snow/config.ini

Example:

    $ python mfe2snow.py alarm="This is my alarm" severity="50"

This is intended to be called as an alarm action to Execute a Script. In the ESM,
go to System Properties | Profile Management | Remote Commands and add a profile for
"Create ServiceNow Ticket". The script can be called using any combination of fields and
values however 'alarm', 'eventdescription', 'severity', 'sourceip' and 'destip' are
mapped to ServiceNow fields. Remaining fields=values are mapped to SNOW field
"Additional Info".

This is an example of the script being called from the ESM Execute Command Profile:

    mfe2snow.py alarm="[$Alarm Name]" eventdescription="[$Rule Message]" severity="[$Average Severity]"
    devicename="[$Device Name]" message_key="[$Event ID]" category="[$Normalized Rule]" sourceip="[$Source IP]"
    destip="[$Destination IP]" sourceport="[$Source Port]" destport="[$Destination Port]" host="[$%HostID]"
    domain="[$%DomainID]" command="[$%CommandID]" object="[$%ObjectID]" application="[$%AppID]"
    deviceaction="[$%Device_Action]" targetuser="[$%UserIDDst]" threatcategory="[$%Threat_Category]"
    threathandled="[$%Threat_Handled]" geosrc="[$Geolocation Source]" geodest="[$Geolocation Destination]"


The output is also written to a file that is overwritten each time the script is run.

Make sure the permissions on the config.ini file are secure as not to expose any credentials.

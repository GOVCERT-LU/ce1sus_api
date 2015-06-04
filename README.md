#ce1sus api

This project contains all the required functionalities to access the ce1sus RESTAPI via Python and also offers
the program to import events from MISP (https://github.com/MISP/MISP) to ce1sus.

#Build Status
[![Code Health](https://landscape.io/github/GOVCERT-LU/ce1sus_api/master/landscape.svg?style=flat)](https://landscape.io/github/GOVCERT-LU/ce1sus_api/master)

# Requirements

* python (2.7+)
* requests (1.3.0+)
* dateutil (1.5+)
* urllib2

#Installation
Install the required libraries and clone the repository.

## Configuration
A template of a configuration file can be found in "ce1sus_adapter.conf_sample".
The configuration file must stored under "~/.ce1sus_adapter.conf".
It contains all the configurations for the different MISPs and Ce1suses.

**Note**: The tag and the text behind the underscore ("_") have to be the same.
This text is used later on to access the corresponding MISP or Ce1sus.

#Documentation
##API
The module using the RESTAPI is located in the ce1sus.api and each function returns a or a list of objects, which can be found in ce1sus.api.classes.

The API has implemented the following:
* Insertion, updates and removal of events, observables, indicators, obects, attributes and attribute/object definitions
* Fetching of events, observables, indicators, obects, attributes and attribute/object definitions by their uuid
* Search for attributes
* login and logouts
* Validation of events

**Note:** As ce1sus is completely RESTfull it is possible to implement more

##Examples
###Import of MISP events
The configuration file contains the following:

``` ini
[misp_cert]
api_url=https://misp1.local.lan
api_key=6789ziu89078tdfghui987tzgu

[ce1sus_local]
api_url=https://ce1sus1.local.lan
api_key=6789ziu89078tzufghui987tzgu

```

The command to import from the event 689 from the MISP "cert" to the ce1sus "local" is the following:

``` shell
./misp_to_ce1sus.py -m cert -c local -e 689
```

To import a misp xml:

``` shell
./misp_to_ce1sus.py -m cert -c local -f file.xml
```

###Fetching of a ce1sus event
``` python

from ce1sus.api.ce1susapi import Ce1susAPI, Ce1susAPIException

ce1sus_api = Ce1susAPI('https://ce1sus1.local.lan', '6789ziu89078tzufghui987tzgu', verify_ssl=False)
ce1sus_api.login()
try:
    event = ce1sus_api.get_event_by_uuid('cea4f050-09d8-11e5-b939-0800200c9a66', True, True)
    print event.to_dict(True, True)
except Ce1susAPIException as error:
    print error
finally:
    ce1sus_api.logout()

```
##Usage

Usage: misp_to_ce1sus.py [options]

Options:

    -h, --help     show this help message and exit

    -m MISP        MISP instance to use

    -c CE1SUS      ce1sus instance to use

    -e MISP_EVENT  MISP event ID

    -v             verbose output

    -d             dry-run, do not store anything in ce1sus

    -r RECENT      import the recent x events

    -f FILE        MISP XML File

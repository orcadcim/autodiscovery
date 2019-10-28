# Orca autodiscovery

This script will run an NMAP scan on the networks attached to your server and create Orca objects in your tenant environment.
A 'prefix' object will be created for the IP addresses on each device that is found.
A 'device' object will be created for each device with a hostname that is found.

## Dependencies

```
pip install netifaces python-nmap requests
```

## Usage

```
$ python3 autodiscovery.py -h
usage: autodiscovery.py [-h] -e  -p  -t

optional arguments:
  -h, --help        show this help message and exit
  -e , --email      Your Orca DCIM email
  -p , --password   Your Orca DCIM password
  -t , --tenant     Your Orca DCIM tenant name

$ python3 autodiscovery.py -t yourtenant -e your@email.com -p yourpassword
```

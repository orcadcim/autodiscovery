# Orca autodiscovery


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

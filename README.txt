
DNS resolver run:

	chmod +x mydig.sh
	./mydig.sh {hostname} {record_type}

Ex: ./mydig.sh amazon.com A

DNSSEC resolver run:
	
	chmod +x mydigsec.sh
	./mydigsec.sh {hostname} {record_type}

Ex: ./mydigsec.sh paypal.com A


2 arguments hostname and record_type are required to be passed for both of the dns resolvers 


The shell script have the following commands:

	#!/bin/sh
	pip install -r requirements.txt
	
	chmod +x mydigsec.py

	python mydigsec.py $1 $2


The dependancies used are as follows:
cffi==1.14.6
cryptography==3.4.8
dnspython==2.1.0
pycparser==2.20

If the shell script doesn't run, please install the dependencies mentioned above and then run the python files

The base python files are mydig.py and mydigsec.py

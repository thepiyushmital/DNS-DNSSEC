#!/bin/sh
pip install -r requirements.txt

chmod +x mydigsec.py

python mydigsec.py $1 $2


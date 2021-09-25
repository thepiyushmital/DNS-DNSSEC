#!/bin/sh
pip install -r requirements.txt

chmod +x mydig.py

python mydig.py $1 $2

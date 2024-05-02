# Bitsquatting

## ZDNS
To download zdns follow the instructions found at:
https://github.com/zmap/zdns
Here are the main ones:
~~~
git clone git@github.com:zmap/zdns.git
cd zdns
go build
~~~

Prerequisites:
* go 

In order to easily use zdns in scripts add the zdns folder that you cloned to your path. 

## Requirements
pip install -r requirements.txt

## Running
Running full_run.py will generate all of the data required for analysis.
Running analysis.py will generate output for our analysis. You will need to update filepaths for new analysis.
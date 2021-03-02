# GET FTD Device Records

## Introduction

The purpose of this set of scripts is to get from FMC all FTD device Records in order to store them somewhere

Among all interesting informations we can extract from this call, we have, the FTD hostname, status, software version, activated licenses, and a lot of other information.

In this example, we store into a csv file only the FTD hostname and it's licenses capabilities

## Installation

Installing these scripts is pretty straight forward . You can just copy / and paste them into you python environment but a good practice is to run them into a python virtual environment.

### Install a Python virtual environment

	For Linux/Mac 

	python3 -m venv venv
	source bin activate

	For Windows 
	
	We assume that you already have installed git-bash.  If so open a git-bash console and :

	python -m venv env 
	venv/Scripts/activate

### git clone the scripts

	git clone https://github.com/pcardotatgit/FMC_Get_Device_Records.git
	cd FMC_Get_Device_Records
	
### install needed modules

FMC_Add_Security_Rules uses the following modules

- requests
- pyyaml
- json
- csv
- pprint
- crayons
	
you can install them with the following  :
	
	pip install -r requirements.txt

## How to use the scripts

- First edit the **fmc_profile.yml** file
- Second test and try to generate an authentication token : **0-fmc_simple_token_request.py**
- Test Rest APIs connectivity to FMC : **1-fmc_system_information.py**  

The **fmc_profile.yml** is a configuration file which contains FMC's IP address, api admin username and password, listening port and API version

Every script starts by reading this file

### Ask for an authentication token to FMC ###

Run the **0-fmc_simple_token_request.py** file.  

It will generate a valid authentication token which will be stored into the **token.txt** file.

This authentication token will be valid during 30 minutes. 

All scripts will read the authentication token from the **token.txt** file and if the token is no longer valid ( error code 401 ), all scripts will automatically ask to FMC for a new authentication token.

### Get device records ###

Run the **2-fmc_get_devices_records.py** script.

This script displays the device records into a json format and store them into the **output_devices_json.json** file

### Convert the JSON Result into a CSV file ###

Run the **3-json_to_csv.py** in order to convert the **output_devices_json.json** file into the **device_records.csv**

It's up to you to merge the 2 last python scripts if you want a one step process.


 
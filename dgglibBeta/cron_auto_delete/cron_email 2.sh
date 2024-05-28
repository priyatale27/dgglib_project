#!/bin/bash

# Change the PATH VALUE here ###############################
virtualEnv=/home/sayanjit/Projects/AXIOM/
delete_script=E:\digital_locker\digilocker\digilockerbackend\cron_auto_delete
############################################################



#This is a bash script will be called inside a cronjob to run and rexecute a python email sender script
# MAIN SCRIPT ########################################
echo Initiating deleting file procedure..
# changing directory
cd $virtualEnv
echo Activating virtual environment..
source venv/bin/activate
cd $delete_script
echo running the mail sending script..
python auto_delete.py
deactivate
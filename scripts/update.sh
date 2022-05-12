#!/bin/sh

echo -n 'Updating Packages ' >> /var/log/update_script.log
echo `date` >> /var/log/update_script.log
echo `sudo apt-get update --yes` >> /var/log/update_script.log
echo `sudo apt-get upgrade --yes` >> /var/log/update_script.log
echo '' >> /var/log/update_script.log

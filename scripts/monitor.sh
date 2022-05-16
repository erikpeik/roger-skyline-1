#!/bin/sh

CRONTAB='/var/spool/cron/crontabs/root'
BACKUP='/var/spool/cron/crontabs/root.backup'

DIFF=`diff $CRONTAB $BACKUP`
if [ ! -z "$DIFF" ]; then
	echo "Crontab file has been changed." | mail -s "Crontab modified" root
fi

cp $CRONTAB $BACKUP

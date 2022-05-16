RED="\e[31m"
GREEN="\e[32m"
ENDCOLOR="\e[0m"

WEB_DIR='/var/www/html'
DEPLOY_DIR='/usr/scripts/deployment'

DIFF=`diff -q $DEPLOY_DIR $WEB_DIR`


if [ ! -z "$DIFF" ]; then
	OUTPUT=$(sudo cp -v $DEPLOY_DIR/* $WEB_DIR)
	echo "New version deployed. $(date)
$DIFF
Changed files:
$OUTPUT" | mail -s "New version deployed" root

	echo "${GREEN}New version deployed. $(date)"
	echo "${ENDCOLOR}$DIFF"
	echo "Changed files:"
	echo "$OUTPUT"
else
	echo "${RED}No files changed. Newest version deployed.${ENDCOLOR}"
fi

#!/bin/sh
#
# zone_cron.sh
#
# version 1.01, 11-14-04, michael@bizsystes.com
#
# dnsbls zone file dump example
#
# 5 minute timeout, extend if necessary
TIMEOUT=300
ZONE_NAME="bl.spamcannibal.org"

DBHOME="/var/run/dbtarpit"
PID_FILE="dnsbls.pid"
SCRIPT_NAME=${0##*/}

# Get the PID of the dnsbls task
DNSBLS_PID=`cat ${DBHOME}/${PID_FILE}`

# Signal dnsbls task to update zone file
kill -USR2 $DNSBLS_PID

echo $$ > ${DBHOME}/${0}.running

# Wait for zone dump task to complete
while  sleep 1; [ $TIMEOUT -gt 0 ] && \
  $([ ! -e ${DBHOME}/${ZONE_NAME}.in ] || \
    [ ${DBHOME}/${ZONE_NAME}.in -ot \
      ${DBHOME}/${SCRIPT_NAME}.running ]);
do  
  TIMEOUT=($TIMEOUT - 1)
done

if [ $TIMEOUT -le 0 ]; then

#  a time out error occured
  echo "timeout error"

else

# do something with the zone file such
# as copy it to and export directory

  cp ${DBHOME}/${ZONE_NAME}.in /usr/local/spamcannibal/public_html
  chmod 644 /usr/local/spamcannibal/public_html/${ZONE_NAME}.in
# save some space
  rm ${DBHOME}/${ZONE_NAME}.in
fi

rm ${DBHOME}/${SCRIPT_NAME}.running

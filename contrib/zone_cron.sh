#!/bin/sh
#
# dnsbls zone file dump example
#
# 5 minute timeout, extend if necessary
TIMEOUT=300
ZONE_NAME="my.zone_name"

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

  cp ${DBHOME}/${ZONE_NAME}.in ./
  echo "zone file update complete"


fi

rm ${DBHOME}/${SCRIPT_NAME}.running

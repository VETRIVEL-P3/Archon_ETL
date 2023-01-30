#!/bin/bash -e
# Archon authentication service

echo "Validating dependency services"
# Validating Database Connectivity
timer=0
while ! nc -z $DATABASE_HOST $DATABASE_PORT; do
    if [[ $timer -le 120 ]]; then
        echo "Validating database connection"
        sleep 3
        timer=$(( timer+3 ))
    else
        echo "Database connection could not be validated. Please Check the availability of Database"
        exit 1
    fi
done
echo "Database connection validated"

# Validating Discovery server
timer=0
echo $DISCOVERY_SERVER_HOST
while ! nc -z $DISCOVERY_SERVER_HOST $DISCOVERY_SERVER_PORT; do
    if [[ $timer -le 120 ]]; then
        echo "Validating Discovery Server connection"
        sleep 3
        timer=$(( timer+3 ))
    else
        echo "Connection to Discovery Server could not be validated. Please Check the availability of Discovery Server"
        exit 1
    fi
done
echo "Connection to Discovery Server validated"

# Validating messaging service
timer=0
while ! nc -z $MESSAGING_SERVICE_HOST $MESSAGING_SERVICE_PORT; do
    if [[ $timer -le 120 ]]; then
        echo "Validating Messaging Service connection"
        sleep 3
        timer=$(( timer+3 ))
    else
        echo "Connection to Messaging Service could not be validated. Please Check the availability of Messaging Service"
        exit 1
    fi
done
echo "Connection to Messaging Service validated"

echo "Starting archon authentication service"

if [[ $SERVER_SSL_ENABLED == true ]]; then
  export EUREKA_NON_SECURE_PORT=false
fi

java $COMMON_MAX_HEAP -jar $APP_HOME/archon-authentication-service-0.0.1-SNAPSHOT.jar --port=$AUTHENTICATION_SERVICE_PORT --property_encryptor_password=$PROPERTY_ENCRYPTOR_KEY

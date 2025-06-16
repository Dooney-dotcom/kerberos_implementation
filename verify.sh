#!/bin/bash

# Esegui il comando 'cat' nel container e poi arresta i container
docker exec echoserver sh -c "cat result.txt && exit"

# Fermare e rimuovere tutti i container
docker-compose down

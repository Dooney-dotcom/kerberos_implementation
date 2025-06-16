#!/bin/bash

# Esegui il build delle immagini Docker
echo "Building the images..."
docker-compose build

# Avvia i server (authserver, tgs, echoserver) in background
echo "Starting the servers..."
docker-compose up -d authserver tgs echoserver

# Esegui il client
echo "Running the client..."
docker-compose run --rm client

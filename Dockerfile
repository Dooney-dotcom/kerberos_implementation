# Usa un'immagine base con Java e JDK
FROM openjdk:17-slim

# Crea una cartella per i file
WORKDIR /app

# Copia i file sorgente
COPY ./src ./src

# Compila tutto all'interno della cartella /src
RUN javac src/kerberos/*.java src/utils/*.java src/digests/*.java src/prngs/*.java

# Comando di default, sovrascrivibile da docker-compose
CMD ["java", "-cp", "src", "kerberos.AuthenticationServer"]

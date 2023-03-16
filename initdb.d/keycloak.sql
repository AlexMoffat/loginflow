-- Create the data base for Keycloak.
CREATE USER keycloak WITH PASSWORD 'HorseHouse';
CREATE DATABASE keycloak WITH OWNER keycloak ENCODING 'UTF8';
# Keycloak Auth Reset Password Sms Provider

Keycloak Auth provider like Send Reset Email but for sending a sms instead

To make Keycloak recognize it the src/main/resources/META-INF folder and its content is required.

## Build

Requirements are Maven (verified 3.6.3) and Java (verified openjdk 1.8.0_322).

To build a .jar file that can be used in Keycloak run the following command

```bash
mvn clean package
```

## Deploy

To deploy it in Keycloak copy the .jar file into the `/opt/keycloak/providers` folder.

When deploying to Docker, copy the file before running `kc.sh build` in the Docker file.

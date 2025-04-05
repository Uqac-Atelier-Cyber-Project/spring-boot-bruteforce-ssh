# spring-boot-bruteforce-ssh

## Description

Ce projet est une application Spring Boot qui exécute des attaques par force brute SSH. Elle utilise un programme C++ pour tester les connexions SSH avec une liste de mots de passe.

## Prérequis

- Java 21 ou supérieur
- Maven 3.6 ou supérieur
- Un compilateur C++ (par exemple, g++)

## Installation

1. Clonez le dépôt :

    ```bash
    git clone https://github.com/Uqac-Atelier-Cyber-Project/spring-boot-bruteforce-ssh.git
    cd spring-boot-bruteforce-ssh
    ```

2. Compilez le programme C++ :

    ```bash
    g++ -o src/main/resources/cppSSHAttack/sshConnexion src/main/resources/cppSSHAttack/sshConnection.cpp -lssh
    ```

3. Construisez le projet Maven :

    ```bash
    mvn clean install
    ```

## Utilisation

1. Démarrez l'application Spring Boot :

    ```bash
    mvn spring-boot:run
    ```

2. Envoyez une requête POST à l'endpoint `/execute-cpp` avec un `ServiceRequest` JSON :

    ```json
    {
        "reportId": 1,
        "option": "IP" // ou "HOSTNAME",
    }
    ```

3. Vérifiez le statut du scan en envoyant une requête GET à l'endpoint `/scan-status/{scanId}`.

4. Generation du JAR avec Maven et installation :

    ```bash
    mvn clean package
    mvn package
    # Execution du JAR
    java -jar target/spring-boot-bruteforce-ssh-0.0.1-SNAPSHOT.jar --api.externe.url=<URL_MAIN_SERVER_API> --server.port=<PORT>
    ```


## Structure du projet

- `src/main/java/com/uqac/bruteforce_ssh` : Contient le code source Java.
- `src/main/resources/cppSSHAttack` : Contient le programme C++ et les fichiers de ressources.

## Dépendances

- Spring Boot
- Jackson
- libssh (pour le programme C++)
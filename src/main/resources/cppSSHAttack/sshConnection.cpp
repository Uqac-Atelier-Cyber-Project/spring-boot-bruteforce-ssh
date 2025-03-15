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
#include <cstdlib> // Pour std::strtol
#include <nlohmann/json.hpp>

using json = nlohmann::json;

/**
 * @brief Vérifier si un port est ouvert sur un hôte
 */
bool isPortOpen(const std::string &host, int port, int timeout_ms) {
    struct sockaddr_in addr;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    struct timeval timeout;
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) <= 0) {
        struct hostent *he = gethostbyname(host.c_str());
        if (he == nullptr) {
            close(sock);
            return false;
        }
        memcpy(&addr.sin_addr, he->h_addr, he->h_length);
    }

    int res = connect(sock, (struct sockaddr *) &addr, sizeof(addr));
    if (res < 0 && errno == EINPROGRESS) {
        fd_set fdset;
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);

        res = select(sock + 1, NULL, &fdset, NULL, &timeout);
        if (res > 0) {
            int so_error;
            socklen_t len = sizeof(so_error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
            close(sock);
            return so_error == 0;
        }
    }

    close(sock);
    return res == 0;
}

/**
 * @brief Tester une connexion SSH
 */
bool trySSHLogin(const std::string &host, const std::string &user, const std::string &password) {
    ssh_session session = ssh_new();
    if (session == nullptr) return false;

    ssh_options_set(session, SSH_OPTIONS_HOST, host.c_str());
    ssh_options_set(session, SSH_OPTIONS_USER, user.c_str());

    if (ssh_connect(session) != SSH_OK) {
        ssh_free(session);
        return false;
    }

    bool success = (ssh_userauth_password(session, nullptr, password.c_str()) == SSH_AUTH_SUCCESS);
    ssh_disconnect(session);
    ssh_free(session);
    return success;
}

/**
 * @brief Fonction principale
 */
int main(int argc, char *argv[]) {
    if (argc != 4) {
        json result = {
            {"reportId", -1},
            {"host", ""},
            {"message", "Arguments invalides"},
            {"error", "Usage: <reportId> <IP> <wordlist_path>"},
            {"user", ""},
            {"password", ""}
        };
        std::cout << result.dump(4) << std::endl;
        return 1;
    }

    // Conversion sécurisée de reportId
    char *endptr;
    long reportId = std::strtol(argv[1], &endptr, 10);
    if (*endptr != '\0' || reportId <= 0) {
        json result = {
            {"reportId", -1},
            {"host", ""},
            {"message", "Argument reportId invalide"},
            {"error", "Le reportId doit être un entier positif"},
            {"user", ""},
            {"password", ""}
        };
        std::cout << result.dump(4) << std::endl;
        return 1;
    }

    std::string host = argv[2];
    std::string wordListPath = argv[3];
    int port = 22;
    int timeout_ms = 5000;

    json result = {
        {"reportId", reportId},
        {"host", host},
        {"message", ""},
        {"error", ""},
        {"user", ""},
        {"password", ""}
    };

    if (!isPortOpen(host, port, timeout_ms)) {
        result["message"] = "Le port 22 (SSH) est fermé";
        std::cout << result.dump(4) << std::endl;
        return 0;
    }

    result["message"] = "Le port 22 (SSH) est ouvert";

    std::ifstream file(wordListPath);
    if (!file.is_open()) {
        result["error"] = "Impossible d'ouvrir le fichier de credentials";
        std::cout << result.dump(4) << std::endl;
        return 1;
    }

    std::string line;
    bool success = false;
    while (std::getline(file, line)) {
        size_t delimiter_pos = line.find(':');
        if (delimiter_pos == std::string::npos) continue;

        std::string user = line.substr(0, delimiter_pos);
        std::string password = line.substr(delimiter_pos + 1);

        if (trySSHLogin(host, user, password)) {
            result["user"] = user;
            result["password"] = password;
            result["message"] = "Connexion SSH réussie";
            success = true;
            break;
        }
    }

    if (!success) {
        result["message"] = "Aucun mot de passe valide trouvé";
    }

    file.close();
    std::cout << result.dump(4) << std::endl;
    return 0;
}

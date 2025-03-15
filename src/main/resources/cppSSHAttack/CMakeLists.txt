cmake_minimum_required(VERSION 3.30)
project(SSHConnexion)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Recherche de la bibliothèque nlohmann_json
find_package(nlohmann_json QUIET)
if(NOT nlohmann_json_FOUND)
    include(FetchContent)
    FetchContent_Declare(
            nlohmann_json
            URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
    )
    FetchContent_MakeAvailable(nlohmann_json)
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBSSH REQUIRED libssh)

# Créer l'exécutable sshConnexion
add_executable(sshConnexion sshConnection.cpp)

# Lier les bibliothèques pour sshConnexion
target_include_directories(sshConnexion PRIVATE ${LIBSSH_INCLUDE_DIRS})
target_link_libraries(sshConnexion PRIVATE nlohmann_json::nlohmann_json ${LIBSSH_LIBRARIES})

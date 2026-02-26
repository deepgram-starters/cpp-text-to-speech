cmake_minimum_required(VERSION 3.20)
project(cpp-text-to-speech LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find dependencies via vcpkg
find_package(Crow CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
find_package(tomlplusplus CONFIG REQUIRED)

add_executable(${PROJECT_NAME} src/main.cpp)

target_link_libraries(${PROJECT_NAME} PRIVATE
    Crow::Crow
    nlohmann_json::nlohmann_json
    OpenSSL::SSL
    OpenSSL::Crypto
    CURL::libcurl
    tomlplusplus::tomlplusplus
)

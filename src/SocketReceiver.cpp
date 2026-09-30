#include "threatfusion/SocketReceiver.h"
#include "threatfusion/DataIngestion.h"
#include "threatfusion/Csv.h"
#include <iostream>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
using socket_t = SOCKET;
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
using socket_t = int;
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket close
#define SD_BOTH SHUT_RDWR
#endif

namespace threatfusion {

SocketReceiver::SocketReceiver() : running_(false) {}
SocketReceiver::~SocketReceiver() { stop(); }

bool SocketReceiver::start(int port, std::function<void(const Event&)> callback) {
    if (listenerThread_.joinable() || port < 1 || port > 65535) return false;
#ifdef _WIN32
    WSADATA data;
    if (WSAStartup(MAKEWORD(2, 2), &data)) return false;
    networkInitialized_ = true;
#endif
    auto fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(static_cast<unsigned short>(port));
    if (fd == INVALID_SOCKET || bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR ||
        listen(fd, 8) == SOCKET_ERROR) {
        if (fd != INVALID_SOCKET) closesocket(fd);
#ifdef _WIN32
        WSACleanup();
        networkInitialized_ = false;
#endif
        return false;
    }
    serverSocket_ = static_cast<std::intptr_t>(fd);
    running_ = true;
    listenerThread_ = std::thread(&SocketReceiver::listenLoop, this, callback);
    return true;
}

void SocketReceiver::stop() {
    running_ = false;
    {
        std::lock_guard<std::mutex> lock(socketMutex_);
        if (clientSocket_ != -1) {
            shutdown(static_cast<socket_t>(clientSocket_), SD_BOTH);
            closesocket(static_cast<socket_t>(clientSocket_));
            clientSocket_ = -1;
        }
        if (serverSocket_ != -1) {
            shutdown(static_cast<socket_t>(serverSocket_), SD_BOTH);
            closesocket(static_cast<socket_t>(serverSocket_));
            serverSocket_ = -1;
        }
    }
    if (listenerThread_.joinable()) listenerThread_.join();
#ifdef _WIN32
    if (networkInitialized_) WSACleanup();
    networkInitialized_ = false;
#endif
}

void SocketReceiver::listenLoop(std::function<void(const Event&)> callback) {
    socket_t server;
    {
        std::lock_guard<std::mutex> lock(socketMutex_);
        server = static_cast<socket_t>(serverSocket_);
    }
    while (running_) {
        auto client = accept(server, nullptr, nullptr);
        if (client == INVALID_SOCKET) break;
        {
            std::lock_guard<std::mutex> lock(socketMutex_);
            clientSocket_ = static_cast<std::intptr_t>(client);
            if (!running_) shutdown(client, SD_BOTH);
        }
        std::string pending;
        char buffer[8192];
        while (running_) {
            const auto received = recv(client, buffer, sizeof(buffer), 0);
            if (received <= 0) break;
            pending.append(buffer, static_cast<std::size_t>(received));
            // Bound incomplete frames before parsing untrusted JSON.
            if (pending.size() > 1024 * 1024) break;
            std::size_t newline;
            while ((newline = pending.find('\n')) != std::string::npos) {
                auto line = pending.substr(0, newline);
                pending.erase(0, newline + 1);
                if (trim(line).empty()) continue;
                try { callback(parseJsonEvent(line)); }
                catch (const std::exception& error) {
                    std::cerr << "[SocketReceiver] Rejected event: " << error.what() << '\n';
                }
            }
        }
        {
            std::lock_guard<std::mutex> lock(socketMutex_);
            if (clientSocket_ != -1) {
                closesocket(client);
                clientSocket_ = -1;
            }
        }
    }
}
} // namespace threatfusion

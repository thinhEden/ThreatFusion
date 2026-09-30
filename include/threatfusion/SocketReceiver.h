#pragma once

#include "Event.h"
#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <cstdint>

namespace threatfusion {

class SocketReceiver {
public:
    SocketReceiver();
    ~SocketReceiver();

    bool start(int port, std::function<void(const Event&)> callback);
    void stop();

private:
    void listenLoop(std::function<void(const Event&)> callback);
    
    std::thread listenerThread_;
    std::atomic<bool> running_;
    std::mutex socketMutex_;
    std::intptr_t serverSocket_ = -1;
    std::intptr_t clientSocket_ = -1;
    bool networkInitialized_ = false;
};

} // namespace threatfusion

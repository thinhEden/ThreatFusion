#pragma once
#include "Event.h"
#include "Detection.h"
#include <string>
#include <vector>

namespace threatfusion {

struct ContextDecision {
    std::vector<Detection> detections;
    std::size_t suppressed = 0;
    std::string policyId;
    std::string reason = "No applicable authorization";
};

class OtContext {
public:
    void load(const std::string& path, bool peerOnlyAblation = false);
    ContextDecision apply(const Event& event, const std::vector<Detection>& detections);
private:
    struct Authorization {
        std::string id, src, dst;
        int unit = -1, firstRegister = 0, lastRegister = 0, minimum = 0, maximum = 0;
        double start = 0, end = 0;
        int budget = 0, used = 0;
        std::vector<int> functions;
    };
    std::vector<Authorization> authorizations_;
    bool peerOnly_ = false;
};
}

#pragma once
#include "Event.h"
#include "Detection.h"
#include <map>
#include <optional>
#include <string>
#include <utility>
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
    // Commissioned value envelope for serial Modbus writes that carry decoded parameters but no register addresses.
    struct Envelope {
        std::string id;
        int unit = -1;
        std::vector<int> functions;
        std::map<std::string, std::vector<double>> allowedValues;
        std::map<std::string, std::pair<double, double>> ranges;
        bool retainStateChanges = false;
    };
    void load(const std::string& path, bool peerOnlyAblation = false);
    // Host alerts (host_ip,timestamp,rule_id,techniques) that disable suppression for commands from that host.
    void loadHostAlerts(const std::string& path, double lookbackSeconds);
    ContextDecision apply(const Event& event, const std::vector<Detection>& detections);
private:
    struct HostAlert {
        std::string ip, ruleId, techniques, timestamp;
        double time = 0;
    };
    ContextDecision applyPolicy(const Event& event, const std::vector<Detection>& detections);
    const HostAlert* hostAlertFor(const Event& event) const;
    std::vector<HostAlert> hostAlerts_;
    double hostLookback_ = 0;
    struct Authorization {
        std::string id, src, dst;
        int unit = -1, firstRegister = 0, lastRegister = 0, minimum = 0, maximum = 0;
        double start = 0, end = 0;
        int budget = 0, used = 0;
        std::vector<int> functions;
    };
    ContextDecision applyEnvelope(const Event& event, const std::vector<Detection>& detections);
    std::vector<Authorization> authorizations_;
    std::optional<Envelope> envelope_;
    std::map<int, std::map<std::string, double>> lastWrite_;
    bool peerOnly_ = false;
};
}

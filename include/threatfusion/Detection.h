#pragma once

#include <string>

namespace threatfusion {

struct Detection {
    std::string eventId;
    std::string source;
    std::string indicator;
    std::string severity;
    std::string category;
    std::string description;
    double confidence = 0.0;
    std::string timestamp;
    std::string srcIp;
    std::string dstIp;
    std::string protocol;
    std::string assetRole;
    std::string attack;  // '|'-joined MITRE ATT&CK technique/software IDs
};

struct Alert {
    std::string incidentId;
    std::string eventId;
    std::string timestamp;
    std::string srcIp;
    std::string dstIp;
    std::string assetRole;
    std::string protocol;
    std::string classification;
    std::string topSeverity;
    double assetCriticality = 0.0;
    double threatSeverity = 0.0;
    double confidenceScore = 0.0;
    int riskScore = 0;
    double latencyMs = 0.0;
    std::string verdict;
    std::string reasons;
    std::string attack;  // Union of detection ATT&CK IDs, sorted and '|'-joined
};

} // namespace threatfusion

#include "threatfusion/RiskScorer.h"

#include "threatfusion/Csv.h"

#include <algorithm>
#include <cmath>
#include <set>
#include <sstream>

namespace threatfusion {

int severityWeight(const std::string& severity) {
    const auto normalized = toLower(severity);
    if (normalized == "critical") return 95;
    if (normalized == "high") return 75;
    if (normalized == "medium") return 50;
    if (normalized == "low") return 25;
    return 10;
}

std::string highestSeverity(const std::vector<Detection>& detections) {
    std::string best = "none";
    int bestScore = 0;
    for (const auto& detection : detections) {
        const auto score = severityWeight(detection.severity);
        if (score > bestScore) {
            bestScore = score;
            best = detection.severity;
        }
    }
    return best;
}

static int assetCriticalityBoost(const std::string& assetRole) {
    const auto role = toLower(assetRole);
    if (role == "plc" || role == "rtu" || role == "safety_controller") return 12;
    if (role == "hmi" || role == "engineering_workstation") return 8;
    if (role == "historian") return 5;
    return 0;
}

static double assetCriticalityScore(const std::string& assetRole) {
    const auto role = toLower(assetRole);
    if (role == "safety_controller") return 5.0;
    if (role == "plc" || role == "rtu") return 4.6;
    if (role == "hmi" || role == "engineering_workstation") return 4.0;
    if (role == "historian") return 3.6;
    return 2.5;
}

static double threatSeverityScore(const std::string& severity) {
    const auto normalized = toLower(severity);
    if (normalized == "critical") return 5.0;
    if (normalized == "high") return 4.2;
    if (normalized == "medium") return 3.0;
    if (normalized == "low") return 1.8;
    return 1.0;
}

Alert RiskScorer::score(const Event& event, const std::vector<Detection>& detections) const {
    Alert alert;
    alert.eventId = event.id;
    alert.timestamp = event.timestamp;
    alert.srcIp = event.srcIp;
    alert.dstIp = event.dstIp;
    alert.assetRole = event.assetRole;
    alert.protocol = event.protocol;
    alert.topSeverity = highestSeverity(detections);
    alert.assetCriticality = assetCriticalityScore(event.assetRole);

    double bestRisk = 0.0;
    double bestThreatSeverity = 0.0;
    double bestConfidence = 0.0;
    std::ostringstream reasons;
    for (std::size_t i = 0; i < detections.size(); ++i) {
        const auto& detection = detections[i];
        const auto threatSeverity = threatSeverityScore(detection.severity);
        const auto confidence = detection.confidence <= 0.0 ? 0.50 : detection.confidence;
        const auto risk = (alert.assetCriticality * threatSeverity * confidence / 25.0) * 100.0;
        if (risk > bestRisk) {
            bestRisk = risk;
            bestThreatSeverity = threatSeverity;
            bestConfidence = confidence;
            alert.classification = detection.category;
        }
        if (i > 0) {
            reasons << " | ";
        }
        reasons << detection.source << ":" << detection.indicator << " ["
                << detection.severity << ", conf=" << confidence << "]";
    }

    if (detections.size() > 1) {
        bestRisk += static_cast<double>((detections.size() - 1) * 8);
    }
    bestRisk += assetCriticalityBoost(event.assetRole);

    alert.threatSeverity = bestThreatSeverity;
    alert.confidenceScore = bestConfidence;
    alert.riskScore = std::min(100, static_cast<int>(std::round(bestRisk)));
    alert.verdict = alert.riskScore >= 80 ? "critical" : alert.riskScore >= 60 ? "malicious" : alert.riskScore >= 35 ? "suspicious" : "benign";
    alert.reasons = reasons.str();

    std::set<std::string> attack;
    for (const auto& detection : detections) {
        for (const auto& id : split(detection.attack, '|')) {
            if (!id.empty()) attack.insert(id);
        }
    }
    for (const auto& id : attack) alert.attack += (alert.attack.empty() ? "" : "|") + id;
    return alert;
}

} // namespace threatfusion

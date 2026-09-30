#include "threatfusion/OtContext.h"
#include "third_party/nlohmann/json.hpp"
#include <algorithm>
#include <cmath>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace threatfusion {
static double utcSeconds(const std::string& value) {
    if (value.find('T') == std::string::npos) {
        std::size_t consumed = 0;
        const double result = std::stod(value, &consumed);
        if (consumed != value.size() || !std::isfinite(result)) throw std::runtime_error("Invalid epoch timestamp");
        return result;
    }
    if (value.size() != 20 || value.back() != 'Z') throw std::runtime_error("Authorization requires UTC Z timestamps");
    std::tm time{};
    std::istringstream input(value);
    input >> std::get_time(&time, "%Y-%m-%dT%H:%M:%SZ");
    if (input.fail()) throw std::runtime_error("Invalid UTC timestamp");
#ifdef _WIN32
    return static_cast<double>(_mkgmtime(&time));
#else
    return static_cast<double>(timegm(&time));
#endif
}

void OtContext::load(const std::string& path, bool peerOnlyAblation) {
    std::ifstream file(path);
    if (!file) throw std::runtime_error("Cannot load OT context: " + path);
    const auto data = nlohmann::json::parse(file);
    authorizations_.clear();
    peerOnly_ = peerOnlyAblation;
    for (const auto& entry : data.at("authorizations")) {
        Authorization auth;
        auth.id = entry.at("ticket_id"); auth.src = entry.at("source_ip"); auth.dst = entry.at("destination_ip");
        auth.unit = entry.at("unit_id"); auth.firstRegister = entry.at("register_start"); auth.lastRegister = entry.at("register_end");
        auth.minimum = entry.at("value_min"); auth.maximum = entry.at("value_max");
        auth.start = utcSeconds(entry.at("start_utc")); auth.end = utcSeconds(entry.at("end_utc"));
        auth.budget = entry.at("max_commands"); auth.functions = entry.at("function_codes").get<std::vector<int>>();
        if (auth.id.empty() || auth.src.empty() || auth.dst.empty() || auth.unit < 0 || auth.unit > 255 ||
            auth.firstRegister < 0 || auth.lastRegister > 65535 || auth.firstRegister > auth.lastRegister ||
            auth.minimum < 0 || auth.maximum > 65535 || auth.minimum > auth.maximum || auth.start >= auth.end || auth.budget <= 0 || auth.functions.empty())
            throw std::runtime_error("Invalid OT authorization");
        for (int function : auth.functions) if (function != 6 && function != 16)
            throw std::runtime_error("Only register writes (6/16) can be authorized by this policy");
        for (const auto& existing : authorizations_) {
            if (existing.src == auth.src && existing.dst == auth.dst && existing.unit == auth.unit &&
                existing.start < auth.end && auth.start < existing.end)
                throw std::runtime_error("Overlapping OT authorizations are ambiguous");
        }
        authorizations_.push_back(auth);
    }
}

ContextDecision OtContext::apply(const Event& event, const std::vector<Detection>& detections) {
    ContextDecision result;
    result.detections = detections;
    if (event.protocol != "modbus" || !event.isRequest || event.registerAddress < 0 || event.registerValues.empty() ||
        event.registerCount < 1 || event.registerValues.size() != static_cast<std::size_t>(event.registerCount)) return result;
    // Corroborating security evidence is never downgraded by a maintenance ticket.
    if (std::any_of(detections.begin(), detections.end(), [](const Detection& d) {
        return !(d.source == "behavior" && d.indicator == "BR-001");
    })) { result.reason = "Independent security evidence retained"; return result; }
    double time;
    try { time = utcSeconds(event.timestamp); }
    catch (...) { result.reason = "Missing or invalid UTC event timestamp"; return result; }
    for (auto& auth : authorizations_) {
        if (event.srcIp != auth.src || event.dstIp != auth.dst) continue;
        if (peerOnly_) {
            result.policyId = auth.id;
            result.reason = "Peer-only ablation (unsafe): command constraints not checked";
            result.suppressed = detections.size();
            result.detections.clear();
            return result;
        }
        if (event.unitId != auth.unit) continue;
        result.policyId = auth.id;
        result.reason = "Authorization constraints not satisfied";
        if (time < auth.start || time >= auth.end ||
            std::find(auth.functions.begin(), auth.functions.end(), event.functionCode) == auth.functions.end() ||
            event.registerAddress < auth.firstRegister || event.registerAddress > auth.lastRegister ||
            static_cast<std::size_t>(auth.lastRegister - event.registerAddress + 1) < event.registerValues.size() ||
            std::any_of(event.registerValues.begin(), event.registerValues.end(), [&](int value) { return value < auth.minimum || value > auth.maximum; })) continue;
        if (auth.used >= auth.budget) { result.reason = "Authorization command budget exhausted"; return result; }
        if (event.functionCode == 6 && event.registerValues.size() != 1) return result;
        ++auth.used;
        result.detections.clear();
        result.suppressed = detections.size();
        result.reason = "Approved bounded register write; ticket constraints satisfied";
        return result;
    }
    return result;
}
}

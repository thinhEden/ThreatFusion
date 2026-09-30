#include "threatfusion/OtContext.h"
#include "threatfusion/Csv.h"
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

static bool isWriteFunction(int function) { return function == 6 || function == 16; }

// Only the write-command rule may be downgraded; any other evidence keeps the alert.
static bool onlyWriteRule(const std::vector<Detection>& detections) {
    return std::all_of(detections.begin(), detections.end(), [](const Detection& d) {
        return d.source == "behavior" && d.indicator == "BR-001";
    });
}

static OtContext::Envelope parseEnvelope(const nlohmann::json& entry) {
    OtContext::Envelope envelope;
    envelope.id = entry.at("id");
    envelope.unit = entry.at("unit_id");
    envelope.functions = entry.at("function_codes").get<std::vector<int>>();
    envelope.retainStateChanges = entry.value("retain_state_changes", false);
    for (const auto& item : entry.at("parameters").items()) {
        const auto& spec = item.value();
        if (spec.contains("values")) {
            auto values = spec.at("values").get<std::vector<double>>();
            if (values.empty()) throw std::runtime_error("Envelope value set is empty: " + item.key());
            envelope.allowedValues[item.key()] = std::move(values);
        } else {
            const double minimum = spec.at("min"), maximum = spec.at("max");
            if (!std::isfinite(minimum) || !std::isfinite(maximum) || minimum > maximum)
                throw std::runtime_error("Invalid envelope range: " + item.key());
            envelope.ranges[item.key()] = {minimum, maximum};
        }
    }
    if (envelope.id.empty() || envelope.unit < 0 || envelope.unit > 255 || envelope.functions.empty() ||
        envelope.allowedValues.size() + envelope.ranges.size() == 0 ||
        !std::all_of(envelope.functions.begin(), envelope.functions.end(), isWriteFunction))
        throw std::runtime_error("Invalid OT operating envelope");
    return envelope;
}

void OtContext::load(const std::string& path, bool peerOnlyAblation) {
    std::ifstream file(path);
    if (!file) throw std::runtime_error("Cannot load OT context: " + path);
    const auto data = nlohmann::json::parse(file);
    authorizations_.clear();
    envelope_.reset();
    lastWrite_.clear();
    peerOnly_ = peerOnlyAblation;
    if (data.contains("operating_envelope")) envelope_ = parseEnvelope(data.at("operating_envelope"));
    for (const auto& entry : data.value("authorizations", nlohmann::json::array())) {
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
        for (int function : auth.functions) if (!isWriteFunction(function))
            throw std::runtime_error("Only register writes (6/16) can be authorized by this policy");
        for (const auto& existing : authorizations_) {
            if (existing.src == auth.src && existing.dst == auth.dst && existing.unit == auth.unit &&
                existing.start < auth.end && auth.start < existing.end)
                throw std::runtime_error("Overlapping OT authorizations are ambiguous");
        }
        authorizations_.push_back(auth);
    }
}

void OtContext::loadHostAlerts(const std::string& path, double lookbackSeconds) {
    if (!(lookbackSeconds > 0)) throw std::runtime_error("Host alert lookback must be positive");
    hostAlerts_.clear();
    hostLookback_ = lookbackSeconds;
    for (const auto& row : readCsv(path)) {
        HostAlert alert;
        alert.ip = row.at("host_ip"); alert.ruleId = row.at("rule_id");
        alert.techniques = row.at("techniques"); alert.timestamp = row.at("timestamp");
        alert.time = utcSeconds(alert.timestamp);
        if (alert.ip.empty() || alert.ruleId.empty()) throw std::runtime_error("Host alert requires host_ip and rule_id");
        hostAlerts_.push_back(alert);
    }
}

// Latest host alert raised on the command's source at or before the command, within the lookback.
const OtContext::HostAlert* OtContext::hostAlertFor(const Event& event) const {
    if (hostAlerts_.empty()) return nullptr;
    double time;
    try { time = utcSeconds(event.timestamp); }
    catch (...) { return nullptr; }
    const HostAlert* latest = nullptr;
    for (const auto& alert : hostAlerts_) {
        if (alert.ip == event.srcIp && alert.time <= time && time - alert.time <= hostLookback_ &&
            (!latest || alert.time > latest->time)) latest = &alert;
    }
    return latest;
}

ContextDecision OtContext::apply(const Event& event, const std::vector<Detection>& detections) {
    // Policy state (ticket budgets, last envelope write) advances even when host evidence overrides the decision.
    auto result = applyPolicy(event, detections);
    if (detections.empty() || !event.isRequest) return result;
    const auto* alert = hostAlertFor(event);
    if (!alert) return result;
    result.detections = detections;
    result.detections.push_back({event.id, "correlation", "HOST-OT-001", "critical", "Command Injection",
        "OT command from a source with host alert " + alert->ruleId + " at " + alert->timestamp, 0.85});
    result.suppressed = 0;
    result.policyId = "HOST-EVIDENCE";
    result.reason = "Host alert " + alert->ruleId + " on " + alert->ip + " at " + alert->timestamp + "; context suppression disabled";
    return result;
}

ContextDecision OtContext::applyPolicy(const Event& event, const std::vector<Detection>& detections) {
    if (envelope_ && event.protocol == "modbus" && event.isRequest && !event.processValues.empty())
        return applyEnvelope(event, detections);
    ContextDecision result;
    result.detections = detections;
    if (event.protocol != "modbus" || !event.isRequest || event.registerAddress < 0 || event.registerValues.empty() ||
        event.registerCount < 1 || event.registerValues.size() != static_cast<std::size_t>(event.registerCount)) return result;
    // Corroborating security evidence is never downgraded by a maintenance ticket.
    if (!onlyWriteRule(detections)) { result.reason = "Independent security evidence retained"; return result; }
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
ContextDecision OtContext::applyEnvelope(const Event& event, const std::vector<Detection>& detections) {
    ContextDecision result;
    result.detections = detections;
    const auto& envelope = *envelope_;
    // Every observed write updates the state, alerted or not, so a change is judged against the actual sequence.
    auto& previous = lastWrite_[event.unitId];
    const bool changed = !previous.empty() && previous != event.processValues;
    previous = event.processValues;
    if (event.unitId != envelope.unit ||
        std::find(envelope.functions.begin(), envelope.functions.end(), event.functionCode) == envelope.functions.end())
        return result;
    result.policyId = envelope.id;
    if (!onlyWriteRule(detections)) { result.reason = "Independent security evidence retained"; return result; }
    for (const auto& [name, allowed] : envelope.allowedValues) {
        const auto value = event.processValues.find(name);
        if (value == event.processValues.end() || std::find(allowed.begin(), allowed.end(), value->second) == allowed.end()) {
            result.reason = "Parameter outside operating envelope: " + name;
            return result;
        }
    }
    for (const auto& [name, range] : envelope.ranges) {
        const auto value = event.processValues.find(name);
        if (value == event.processValues.end() || value->second < range.first || value->second > range.second) {
            result.reason = "Parameter outside operating envelope: " + name;
            return result;
        }
    }
    if (envelope.retainStateChanges && changed) { result.reason = "State change retained for review"; return result; }
    result.detections.clear();
    result.suppressed = detections.size();
    result.reason = "Write inside commissioned operating envelope";
    return result;
}
}

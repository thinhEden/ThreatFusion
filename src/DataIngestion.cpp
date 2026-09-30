#include "threatfusion/DataIngestion.h"

#include "threatfusion/Csv.h"
#include "threatfusion/Process.h"
#include "third_party/nlohmann/json.hpp"

#include <cmath>
#include <limits>
#include <fstream>
#include <stdexcept>

namespace threatfusion {

static int parseInt(const CsvRow& row, const std::string& key, int fallback = 0) {
    const auto found = row.find(key);
    if (found == row.end() || found->second.empty()) {
        return fallback;
    }
    return std::stoi(found->second);
}

static std::vector<Event> loadCsvEvents(const std::string& path) {
    std::vector<Event> events;
    for (const auto& row : readCsv(path)) {
        Event event;
        event.id = row.at("id");
        event.timestamp = row.at("timestamp");
        event.srcIp = row.at("src_ip");
        event.dstIp = row.at("dst_ip");
        event.protocol = row.at("protocol");
        event.functionCode = parseInt(row, "function_code", -1);
        event.assetRole = row.at("asset_role");
        event.payloadHash = row.at("payload_hash");
        event.payloadPath = row.count("payload_path") ? row.at("payload_path") : "";
        event.bytes = parseInt(row, "bytes", 0);
        event.action = row.at("action");
        event.label = row.count("label") ? row.at("label") : "";
        events.push_back(event);
    }
    return events;
}


static std::vector<Event> loadJsonlEvents(const std::string& path) {
    std::ifstream file(path);
    if (!file) {
        throw std::runtime_error("Cannot open JSONL file: " + path);
    }

    std::vector<Event> events;
    std::string line;
    while (std::getline(file, line)) {
        if (trim(line).empty()) {
            continue;
        }
        events.push_back(parseJsonEvent(line));
    }
    return events;
}

Event parseJsonEvent(const std::string& line) {
    const auto data = nlohmann::json::parse(line);
    if (!data.is_object()) throw std::runtime_error("Event must be a JSON object");
    auto integer = [&](const char* key, int fallback) {
        if (!data.contains(key)) return fallback;
        const auto& value = data.at(key);
        if (!value.is_number_integer()) throw std::runtime_error(std::string("Integer field required: ") + key);
        if (value.is_number_unsigned() && value.get<unsigned long long>() > static_cast<unsigned long long>(std::numeric_limits<int>::max()))
            throw std::runtime_error("Integer field out of range");
        const auto parsed = value.get<long long>();
        if (parsed < std::numeric_limits<int>::min() || parsed > std::numeric_limits<int>::max())
            throw std::runtime_error("Integer field out of range");
        return static_cast<int>(parsed);
    };
    Event event;
    event.id = data.value("id", std::string{});
    if (event.id.empty()) throw std::runtime_error("Event id is required");
    event.timestamp = data.value("timestamp", std::string{});
    event.srcIp = data.value("src_ip", std::string{});
    event.dstIp = data.value("dst_ip", std::string{});
    event.protocol = data.value("protocol", std::string{});
    event.functionCode = integer("function_code", -1);
    event.assetRole = data.value("asset_role", std::string{});
    event.payloadHash = data.value("payload_hash", std::string{});
    event.payloadPath = data.value("payload_path", std::string{});
    event.bytes = integer("bytes", 0);
    event.action = data.value("action", std::string{});
    event.label = data.value("label", std::string{});
    event.extraFeatures = data.value("extra_features", std::vector<double>{});
    event.unitId = integer("unit_id", -1);
    event.registerAddress = integer("register_address", -1);
    event.registerCount = integer("register_count", -1);
    if (data.contains("register_values")) {
        if (!data.at("register_values").is_array()) throw std::runtime_error("Register values must be an array");
        for (const auto& value : data.at("register_values")) {
            if (!value.is_number_integer() || value.get<long long>() < 0 || value.get<long long>() > 65535)
                throw std::runtime_error("Register values must be unsigned 16-bit integers");
            event.registerValues.push_back(value.get<int>());
        }
    }
    event.isRequest = data.value("is_request", false);
    if (data.contains("process_values")) {
        const auto& values = data.at("process_values");
        if (!values.is_object()) throw std::runtime_error("Process values must be an object");
        for (const auto& item : values.items()) {
            if (!item.value().is_number() || !std::isfinite(item.value().get<double>()))
                throw std::runtime_error("Process values must be finite numbers");
            event.processValues[item.key()] = item.value().get<double>();
        }
    }
    for (double feature : event.extraFeatures) {
        if (!std::isfinite(feature)) throw std::runtime_error("Feature must be finite");
    }
    return event;
}

std::string eventJson(const Event& event) {
    return nlohmann::json{
        {"id", event.id}, {"timestamp", event.timestamp}, {"src_ip", event.srcIp},
        {"dst_ip", event.dstIp}, {"protocol", event.protocol}, {"function_code", event.functionCode},
        {"asset_role", event.assetRole}, {"payload_hash", event.payloadHash}, {"payload_path", event.payloadPath},
        {"bytes", event.bytes}, {"action", event.action}, {"label", event.label},
        {"extra_features", event.extraFeatures}, {"unit_id", event.unitId},
        {"register_address", event.registerAddress}, {"register_count", event.registerCount}, {"register_values", event.registerValues},
        {"is_request", event.isRequest}, {"process_values", event.processValues}}.dump();
}


static int firstFunctionCode(const std::vector<std::string>& columns) {
    for (std::size_t i = 5; i <= 9 && i < columns.size(); ++i) {
        if (!columns[i].empty()) {
            try {
                return std::stoi(columns[i]);
            } catch (...) {
                return -1;
            }
        }
    }
    return -1;
}

static int safeInt(const std::string& value, int fallback = 0) {
    if (value.empty()) {
        return fallback;
    }
    try {
        return std::stoi(value);
    } catch (...) {
        return fallback;
    }
}

static std::string normalizeProtocol(const std::string& raw) {
    const auto value = toLower(raw);
    if (value.find("modbus") != std::string::npos) return "modbus";
    if (value.find("dnp3") != std::string::npos) return "dnp3";
    if (value.find("iec") != std::string::npos || value.find("104") != std::string::npos) return "iec104";
    if (value.find("61850") != std::string::npos || value.find("mms") != std::string::npos) return "iec61850";
    if (value.find("opc") != std::string::npos) return "opcua";
    if (value.find("bacnet") != std::string::npos || value.find("bvlc") != std::string::npos) return "bacnet";
    if (value.find("codesys") != std::string::npos) return "codesys";
    if (value.find("s7") != std::string::npos) return "s7comm";
    return value.empty() ? "unknown" : value;
}

static std::string inferAssetRole(const std::string& protocol) {
    const auto value = toLower(protocol);
    if (value == "modbus" || value == "s7comm" || value == "codesys") return "plc";
    if (value == "dnp3" || value == "iec104" || value == "iec61850") return "rtu";
    if (value == "opcua") return "historian";
    if (value == "bacnet") return "hmi";
    return "unknown";
}

static std::vector<Event> loadPcapEvents(const std::string& path, const std::string& tsharkPath, const std::string& filter) {
    std::vector<std::string> arguments = {"-r", path, "-T", "fields", "-E", "separator=,", "-E", "quote=d", "-E", "occurrence=a"};
    if (!filter.empty()) { arguments.push_back("-Y"); arguments.push_back(filter); }
    for (const auto& field : {"frame.number", "frame.time_epoch", "ip.src", "ip.dst", "_ws.col.Protocol", "modbus.func_code",
         "dnp3.al.func", "104asdu.typeid", "opcua.transport.type", "bacapp.type", "frame.len", "mbtcp.unit_id",
         "modbus.reference_num", "modbus.regval_uint16", "tcp.dstport", "modbus.word_cnt"}) { arguments.push_back("-e"); arguments.push_back(field); }
    const auto output = processOutput(tsharkPath, arguments);
    if (output.empty()) {
        throw std::runtime_error("No PCAP events parsed. Is tshark installed and in PATH?");
    }

    std::vector<Event> events;
    for (const auto& line : split(output, '\n')) {
        if (trim(line).empty()) {
            continue;
        }
        const auto columns = parseCsvLine(line);
        if (columns.size() < 5) {
            continue;
        }
        Event event;
        event.id = "PCAP-" + columns[0];
        event.timestamp = columns.size() > 1 ? columns[1] : "";
        event.srcIp = columns.size() > 2 ? columns[2] : "";
        event.dstIp = columns.size() > 3 ? columns[3] : "";
        event.protocol = normalizeProtocol(columns.size() > 4 ? columns[4] : "");
        event.functionCode = firstFunctionCode(columns);
        event.assetRole = inferAssetRole(event.protocol);
        event.payloadHash = "";
        event.bytes = columns.size() > 10 ? safeInt(columns[10], 0) : 0;
        event.unitId = columns.size() > 11 ? safeInt(columns[11], -1) : -1;
        event.registerAddress = columns.size() > 12 ? safeInt(columns[12], -1) : -1;
        if (columns.size() > 13 && !columns[13].empty()) {
            for (const auto& value : split(columns[13], ',')) event.registerValues.push_back(safeInt(value, -1));
        }
        event.isRequest = columns.size() > 14 && columns[14] == "502";
        event.registerCount = event.functionCode == 6 ? 1 : columns.size() > 15 ? safeInt(columns[15], -1) : -1;
        event.action = event.isRequest ? "request" : "observed";
        event.label = "";
        // tshark aggregates fields from multiple ADUs in one frame. Their register
        // fields cannot safely be paired, so retain each function and deny authorization.
        bool aggregated = false;
        for (const auto index : {5u, 11u, 12u, 15u})
            if (columns.size() > index && columns[index].find(',') != std::string::npos) aggregated = true;
        if (event.protocol == "modbus" && aggregated) {
            const auto functions = split(columns[5], ',');
            for (std::size_t i = 0; i < functions.size(); ++i) {
                auto part = event;
                part.id += "-ADU-" + std::to_string(i + 1);
                part.functionCode = safeInt(functions[i], -1);
                part.unitId = part.registerAddress = part.registerCount = -1;
                part.registerValues.clear();
                part.action = "aggregated_modbus_requires_review";
                events.push_back(std::move(part));
            }
        } else {
            events.push_back(event);
        }
    }
    return events;
}

std::vector<Event> loadEvents(const std::string& path, const IngestionOptions& options) {
    const auto normalized = toLower(options.format);
    if (normalized == "csv") {
        return loadCsvEvents(path);
    }
    if (normalized == "jsonl" || normalized == "json") {
        return loadJsonlEvents(path);
    }
    if (normalized == "pcap") {
        return loadPcapEvents(path, options.tsharkPath, options.pcapFilter);
    }
    throw std::runtime_error("Unsupported event format: " + options.format);
}

std::vector<Event> loadEvents(const std::string& path, const std::string& format) {
    IngestionOptions options;
    options.format = format;
    return loadEvents(path, options);
}

} // namespace threatfusion

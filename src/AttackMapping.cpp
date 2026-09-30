#include "threatfusion/AttackMapping.h"

#include "threatfusion/Csv.h"

#include <regex>

namespace threatfusion {

// Suricata fast.log lines carry "[gid:sid:rev]"; YARA prints "RuleName target".
static std::string mappingKey(const Detection& detection) {
    if (detection.source == "suricata") {
        static const std::regex sid(R"(\[\d+:(\d+):\d+\])");
        std::smatch match;
        return std::regex_search(detection.indicator, match, sid) ? match[1].str() : "";
    }
    if (detection.source == "yara") return detection.indicator.substr(0, detection.indicator.find(' '));
    return detection.indicator;
}

void AttackMapping::load(const std::string& path) {
    ids_.clear();
    for (const auto& row : readCsv(path)) {
        std::string ids = row.at("techniques");
        const auto& software = row.at("software");
        if (!software.empty()) ids += (ids.empty() ? "" : "|") + software;
        if (!ids.empty()) ids_[{row.at("source"), row.at("indicator")}] = ids;
    }
}

std::string AttackMapping::lookup(const Detection& detection) const {
    const auto found = ids_.find({detection.source, mappingKey(detection)});
    return found == ids_.end() ? "" : found->second;
}

} // namespace threatfusion

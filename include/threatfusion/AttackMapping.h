#pragma once

#include "Detection.h"

#include <map>
#include <string>
#include <utility>

namespace threatfusion {

// Maps detections to MITRE ATT&CK technique and software IDs from data/attack_mapping.csv.
class AttackMapping {
public:
    void load(const std::string& path);
    std::string lookup(const Detection& detection) const;

private:
    std::map<std::pair<std::string, std::string>, std::string> ids_;
};

} // namespace threatfusion

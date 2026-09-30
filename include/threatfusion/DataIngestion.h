#pragma once

#include "threatfusion/Event.h"

#include <string>
#include <vector>

namespace threatfusion {

struct IngestionOptions {
    std::string format = "csv";
    std::string tsharkPath = "tshark";
    std::string pcapFilter;
};

Event parseJsonEvent(const std::string& line);
std::string eventJson(const Event& event);

std::vector<Event> loadEvents(const std::string& path, const IngestionOptions& options);
std::vector<Event> loadEvents(const std::string& path, const std::string& format);

} // namespace threatfusion

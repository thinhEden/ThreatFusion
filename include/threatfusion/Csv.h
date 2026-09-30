#pragma once

#include <map>
#include <string>
#include <vector>
#include <ostream>

namespace threatfusion {
void writeCsvRow(std::ostream& stream, const std::vector<std::string>& row);
void appendCsv(const std::string& path, const std::vector<std::string>& headers,
               const std::vector<std::string>& row);

using CsvRow = std::map<std::string, std::string>;

std::vector<std::string> parseCsvLine(const std::string& line);
std::vector<CsvRow> readCsv(const std::string& path);
void writeCsv(const std::string& path,
              const std::vector<std::string>& headers,
              const std::vector<std::vector<std::string>>& rows);

void ensureParentDirectory(const std::string& path);
std::string trim(const std::string& value);
std::string toLower(std::string value);
std::vector<std::string> split(const std::string& value, char delimiter);

} // namespace threatfusion

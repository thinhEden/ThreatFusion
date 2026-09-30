#include "threatfusion/Csv.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <filesystem>
#include <stdexcept>

#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#endif

namespace threatfusion {

std::string trim(const std::string& value) {
    auto begin = std::find_if_not(value.begin(), value.end(), [](unsigned char c) {
        return std::isspace(c) != 0;
    });
    auto end = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char c) {
        return std::isspace(c) != 0;
    }).base();
    if (begin >= end) {
        return "";
    }
    return std::string(begin, end);
}

std::string toLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::vector<std::string> split(const std::string& value, char delimiter) {
    std::vector<std::string> parts;
    std::string current;
    for (char c : value) {
        if (c == delimiter) {
            parts.push_back(trim(current));
            current.clear();
        } else {
            current.push_back(c);
        }
    }
    parts.push_back(trim(current));
    return parts;
}

std::vector<std::string> parseCsvLine(const std::string& line) {
    std::vector<std::string> columns;
    std::string current;
    bool inQuotes = false;

    for (std::size_t i = 0; i < line.size(); ++i) {
        const char c = line[i];
        if (c == '"') {
            if (inQuotes && i + 1 < line.size() && line[i + 1] == '"') {
                current.push_back('"');
                ++i;
            } else {
                inQuotes = !inQuotes;
            }
        } else if (c == ',' && !inQuotes) {
            columns.push_back(trim(current));
            current.clear();
        } else {
            current.push_back(c);
        }
    }
    columns.push_back(trim(current));
    return columns;
}

std::vector<CsvRow> readCsv(const std::string& path) {
    std::ifstream file(path);
    if (!file) {
        throw std::runtime_error("Cannot open CSV file: " + path);
    }

    std::string headerLine;
    if (!std::getline(file, headerLine)) {
        return {};
    }

    auto headers = parseCsvLine(headerLine);
    std::vector<CsvRow> rows;
    std::string line;
    while (std::getline(file, line)) {
        if (trim(line).empty()) {
            continue;
        }
        auto values = parseCsvLine(line);
        CsvRow row;
        for (std::size_t i = 0; i < headers.size(); ++i) {
            row[headers[i]] = i < values.size() ? values[i] : "";
        }
        rows.push_back(row);
    }
    return rows;
}

static std::string escapeCsv(const std::string& value) {
    const bool needsQuotes = value.find_first_of(",\"\n\r") != std::string::npos;
    if (!needsQuotes) {
        return value;
    }
    std::string escaped = "\"";
    for (char c : value) {
        if (c == '"') {
            escaped += "\"\"";
        } else {
            escaped.push_back(c);
        }
    }
    escaped.push_back('"');
    return escaped;
}

static void makeDirectory(const std::string& path) {
    if (path.empty()) {
        return;
    }
#ifdef _WIN32
    _mkdir(path.c_str());
#else
    mkdir(path.c_str(), 0755);
#endif
}

void ensureParentDirectory(const std::string& path) {
    const auto slash = path.find_last_of("/\\");
    if (slash == std::string::npos) {
        return;
    }

    const auto parent = path.substr(0, slash);
    std::string current;
    for (char c : parent) {
        current.push_back(c);
        if (c == '/' || c == '\\') {
            if (current.size() > 1 && current[current.size() - 2] != ':') {
                makeDirectory(current);
            }
        }
    }
    makeDirectory(parent);
}

void writeCsv(const std::string& path,
              const std::vector<std::string>& headers,
              const std::vector<std::vector<std::string>>& rows) {
    ensureParentDirectory(path);

    std::ofstream file(path);
    if (!file) {
        throw std::runtime_error("Cannot write CSV file: " + path);
    }

    for (std::size_t i = 0; i < headers.size(); ++i) {
        if (i > 0) {
            file << ',';
        }
        file << escapeCsv(headers[i]);
    }
    file << '\n';

    for (const auto& row : rows) {
        for (std::size_t i = 0; i < row.size(); ++i) {
            if (i > 0) {
                file << ',';
            }
            file << escapeCsv(row[i]);
        }
        file << '\n';
    }
}

void writeCsvRow(std::ostream& stream, const std::vector<std::string>& row) {
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (i) stream << ',';
        stream << escapeCsv(row[i]);
    }
    stream << '\n';
    if (!stream) throw std::runtime_error("Cannot write CSV row");
}

void appendCsv(const std::string& path, const std::vector<std::string>& headers,
               const std::vector<std::string>& row) {
    auto file = openCsvAppend(path, headers);
    writeCsvRow(file, row);
}

std::ofstream openCsvAppend(const std::string& path, const std::vector<std::string>& headers) {
    ensureParentDirectory(path);
    std::ifstream existing(path, std::ios::binary | std::ios::ate);
    bool needsHeader = !existing || existing.tellg() == 0;
    if (!needsHeader) {
        existing.seekg(0);
        std::string header;
        std::getline(existing, header);
        if (parseCsvLine(header) != headers) {
            existing.close();
            // Preserve logs from an earlier schema rather than appending unreadable rows.
            std::string backup;
            for (unsigned n = 1; ; ++n) {
                backup = path + ".schema-" + std::to_string(n) + ".bak";
                if (!std::filesystem::exists(backup)) break;
            }
            std::filesystem::rename(path, backup);
            needsHeader = true;
        }
    }
    existing.close();
    std::ofstream file(path, std::ios::app);
    if (!file) throw std::runtime_error("Cannot append CSV: " + path);
    if (needsHeader) writeCsvRow(file, headers);
    return file;
}

} // namespace threatfusion

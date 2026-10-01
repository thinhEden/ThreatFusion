#include "threatfusion/IsolationForestDetector.h"

#include "threatfusion/Csv.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <numeric>
#include <stdexcept>

namespace threatfusion {

static double hashUnit(const std::string& value) {
    std::hash<std::string> hasher;
    return static_cast<double>(hasher(value) % 10000) / 10000.0;
}

static double protocolCode(const std::string& protocol) {
    const auto value = toLower(protocol);
    if (value == "modbus") return 0.10;
    if (value == "dnp3") return 0.20;
    if (value == "iec104") return 0.30;
    if (value == "iec61850") return 0.40;
    if (value == "opcua") return 0.50;
    if (value == "bacnet") return 0.60;
    if (value == "s7comm") return 0.70;
    if (value == "tcp") return 0.80;
    return 0.95;
}

static double assetCode(const std::string& assetRole) {
    const auto value = toLower(assetRole);
    if (value == "plc") return 0.15;
    if (value == "rtu") return 0.25;
    if (value == "hmi") return 0.35;
    if (value == "engineering_workstation") return 0.45;
    if (value == "historian") return 0.55;
    if (value == "safety_controller") return 0.65;
    return 0.95;
}

static double hourValue(const std::string& timestamp) {
    if (timestamp.size() >= 13) {
        try {
            return std::stoi(timestamp.substr(11, 2)) / 23.0;
        } catch (...) {
            return 0.0;
        }
    }
    return 0.0;
}

std::vector<double> IsolationForestDetector::features(const Event& event) {
    std::vector<double> base = {
        hashUnit(event.srcIp),
        hashUnit(event.dstIp),
        protocolCode(event.protocol),
        std::max(0.0, std::min(1.0, static_cast<double>(event.functionCode) / 255.0)),
        assetCode(event.assetRole),
        std::min(1.0, std::log1p(static_cast<double>(std::max(0, event.bytes))) / std::log(2000000.0)),
        hourValue(event.timestamp)
    };
    for (double val : event.extraFeatures) {
        base.push_back(val);
    }
    return base;
}

static double cFactor(int n) {
    if (n <= 1) return 0.0;
    if (n == 2) return 1.0;
    const auto harmonic = std::log(static_cast<double>(n - 1)) + 0.5772156649;
    return 2.0 * harmonic - (2.0 * (n - 1) / static_cast<double>(n));
}

static int buildTree(IsolationForestDetector::Tree& tree,
                     const std::vector<std::vector<double>>& points,
                     const std::vector<int>& indices,
                     int depth,
                     int maxDepth,
                     std::mt19937& rng) {
    typename IsolationForestDetector::Node node;
    node.size = static_cast<int>(indices.size());
    const int nodeIndex = static_cast<int>(tree.nodes.size());
    tree.nodes.push_back(node);

    if (indices.size() <= 1 || depth >= maxDepth) {
        return nodeIndex;
    }

    std::vector<int> activeFeatures;
    for (int f = 0; f < static_cast<int>(points[0].size()); ++f) {
        double minVal = std::numeric_limits<double>::max();
        double maxVal = std::numeric_limits<double>::lowest();
        for (const auto index : indices) {
            minVal = std::min(minVal, points[index][f]);
            maxVal = std::max(maxVal, points[index][f]);
        }
        if (minVal < maxVal) {
            activeFeatures.push_back(f);
        }
    }

    if (activeFeatures.empty()) {
        return nodeIndex;
    }

    std::uniform_int_distribution<int> featureDist(0, static_cast<int>(activeFeatures.size()) - 1);
    int feature = activeFeatures[featureDist(rng)];
    double minValue = std::numeric_limits<double>::max();
    double maxValue = std::numeric_limits<double>::lowest();
    for (const auto index : indices) {
        minValue = std::min(minValue, points[index][feature]);
        maxValue = std::max(maxValue, points[index][feature]);
    }

    std::uniform_real_distribution<double> splitDist(minValue, maxValue);
    const auto split = splitDist(rng);
    std::vector<int> left;
    std::vector<int> right;
    for (const auto index : indices) {
        if (points[index][feature] < split) {
            left.push_back(index);
        } else {
            right.push_back(index);
        }
    }

    if (left.empty() || right.empty()) {
        return nodeIndex;
    }

    int leftChild = buildTree(tree, points, left, depth + 1, maxDepth, rng);
    int rightChild = buildTree(tree, points, right, depth + 1, maxDepth, rng);

    tree.nodes[nodeIndex].leaf = false;
    tree.nodes[nodeIndex].feature = feature;
    tree.nodes[nodeIndex].split = split;
    tree.nodes[nodeIndex].left = leftChild;
    tree.nodes[nodeIndex].right = rightChild;
    return nodeIndex;
}

void IsolationForestDetector::train(const std::vector<Event>& events, int treeCount, int maxDepth, unsigned seed) {
    trees_.clear();
    maxDepth_ = maxDepth;
    std::vector<std::vector<double>> points;
    for (const auto& event : events) {
        if (toLower(event.label) == "malicious") {
            continue;
        }
        points.push_back(features(event));
    }
    if (points.size() < 2) {
        sampleSize_ = static_cast<int>(points.size());
        return;
    }
    featureDim_ = points.front().size();
    for (const auto& point : points) {
        if (point.size() != featureDim_) throw std::runtime_error("Inconsistent baseline feature dimensions");
    }
    sampleSize_ = static_cast<int>(std::min<std::size_t>(points.size(), 256));

    std::mt19937 rng(seed);
    std::vector<int> indices(points.size());
    std::iota(indices.begin(), indices.end(), 0);

    for (int i = 0; i < treeCount; ++i) {
        std::shuffle(indices.begin(), indices.end(), rng);
        const auto sampleCount = std::min<std::size_t>(indices.size(), 256);
        std::vector<int> sample(indices.begin(), indices.begin() + sampleCount);
        Tree tree;
        buildTree(tree, points, sample, 0, maxDepth_, rng);
        trees_.push_back(tree);
    }
}

double IsolationForestDetector::pathLength(const Tree& tree, const std::vector<double>& point) {
    int nodeIndex = 0;
    int depth = 0;
    while (nodeIndex >= 0 && nodeIndex < static_cast<int>(tree.nodes.size())) {
        const auto& node = tree.nodes[nodeIndex];
        if (node.leaf) {
            return depth + cFactor(node.size);
        }
        nodeIndex = point[node.feature] < node.split ? node.left : node.right;
        ++depth;
    }
    return depth;
}

double IsolationForestDetector::anomalyScore(const Event& event) const {
    if (empty()) return 0.0;
    const auto point = features(event);
    if (point.size() != featureDim_) throw std::runtime_error("Event feature dimensions do not match Isolation Forest baseline");
    double totalPath = 0.0;
    for (const auto& tree : trees_) {
        totalPath += pathLength(tree, point);
    }
    const auto avgPath = totalPath / static_cast<double>(trees_.size());
    return std::pow(2.0, -avgPath / std::max(0.0001, cFactor(sampleSize_)));
}

std::vector<Detection> IsolationForestDetector::evaluate(const Event& event) const {
    std::vector<Detection> detections;
    if (empty()) return detections;
    const auto score = anomalyScore(event);

    if (score >= threshold_) {
        detections.push_back({
            event.id,
            "isolation_forest",
            "score:" + std::to_string(score),
            score >= 0.70 ? "high" : "medium",
            "Anomaly Detection",
            "Isolation Forest anomaly score exceeded the OT baseline threshold.",
            std::min(0.95, score)
        });
    }
    return detections;
}

} // namespace threatfusion

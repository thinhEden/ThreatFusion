#pragma once

#include "threatfusion/Detection.h"
#include "threatfusion/Event.h"

#include <random>
#include <string>
#include <vector>

namespace threatfusion {

class IsolationForestDetector {
public:
    void train(const std::vector<Event>& events, int treeCount = 25, int maxDepth = 8);
    std::vector<Detection> evaluate(const Event& event) const;
    double anomalyScore(const Event& event) const;
    bool empty() const { return trees_.empty(); }

    struct Node {
        bool leaf = true;
        int feature = 0;
        double split = 0.0;
        int left = -1;
        int right = -1;
        int size = 0;
    };

    struct Tree {
        std::vector<Node> nodes;
    };

private:
    std::vector<Tree> trees_;
    int maxDepth_ = 8;
    int sampleSize_ = 0;
    std::size_t featureDim_ = 0;

    static std::vector<double> features(const Event& event);
    static double pathLength(const Tree& tree, const std::vector<double>& point);
};

} // namespace threatfusion

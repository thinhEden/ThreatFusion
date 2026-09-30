#pragma once

#include "Event.h"
#include "Detection.h"

#include <string>
#include <vector>
#include <map>
#include <deque>
#include <optional>

#ifdef USE_LIBTORCH
namespace torch {
namespace jit {
struct Module;
}
}
#endif

namespace threatfusion {

class LSTMDetector {
public:
    LSTMDetector();
    ~LSTMDetector();

    bool loadModel(const std::string& modelPath);
    std::vector<Detection> evaluate(const Event& event);
    
    bool empty() const { return !modelLoaded_; }
    std::optional<double> lastError() const { return lastError_; }

private:
    std::vector<double> extractFeatures(const Event& event) const;

    bool modelLoaded_ = false;
    std::string modelPath_;
    int windowSize_ = 10;      // Sliding window size W
    int featureDim_ = 7;       // Dimensionality D (updated dynamically if extraFeatures present)
    bool featureDimSet_ = false;
    double anomalyThreshold_ = 0.003;
    std::optional<double> lastError_;
    bool simulated_ = false;

    // Track sliding window of feature vectors per source IP
    std::map<std::string, std::deque<std::vector<double>>> flowWindows_;

#ifdef USE_LIBTORCH
    // LibTorch model module pointer wrapper to avoid headers when not compiling with LibTorch
    void* torchModule_ = nullptr; 
#endif
};

} // namespace threatfusion

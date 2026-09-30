#pragma once

#include <string>
#include <vector>

namespace threatfusion {

struct Event {
    std::string id;
    std::string timestamp;
    std::string srcIp;
    std::string dstIp;
    std::string protocol;
    int functionCode = -1;
    std::string assetRole;
    std::string payloadHash;
    std::string payloadPath;
    int bytes = 0;
    std::string action;
    std::string label;

    // Optional process-level numeric features (e.g. PipelinePSI, SetPoint,
    // deltaPipelinePSI, deltaSetPoint, TimeInterval from MSU ICS dataset).
    // These are normalized to [0,1] by the dataset normalizer and appended
    // to the LSTM feature vector for richer anomaly detection.
    std::vector<double> extraFeatures;
    int unitId = -1;
    int registerAddress = -1;
    int registerCount = -1;
    std::vector<int> registerValues;
    bool isRequest = false;
};

} // namespace threatfusion

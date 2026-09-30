#include "threatfusion/LSTMDetector.h"
#include "threatfusion/Csv.h"

#include <algorithm>
#include <cmath>
#include <iostream>
#include <numeric>
#include <cstdint>
#include <fstream>
#include <stdexcept>
#include "third_party/nlohmann/json.hpp"

#ifdef USE_LIBTORCH
#include <torch/script.h>
#include <ATen/Parallel.h>
#endif

namespace threatfusion {

// Helper encoders matching Isolation Forest features
static double hashUnit(const std::string &value) {
  if (value.empty()) return 0.0;
  uint64_t hash = 14695981039346656037ull;
  for (unsigned char c : value) {
    hash ^= static_cast<uint64_t>(c);
    hash *= 1099511628211ull;
  }
  return static_cast<double>(hash % 10000) / 10000.0;
}

static double protocolCode(const std::string &protocol) {
  const auto value = toLower(protocol);
  if (value == "modbus")
    return 0.10;
  if (value == "dnp3")
    return 0.20;
  if (value == "iec104")
    return 0.30;
  if (value == "iec61850")
    return 0.40;
  if (value == "opcua")
    return 0.50;
  if (value == "bacnet")
    return 0.60;
  if (value == "s7comm")
    return 0.70;
  if (value == "tcp")
    return 0.80;
  return 0.95;
}

static double assetCode(const std::string &assetRole) {
  const auto value = toLower(assetRole);
  if (value == "plc")
    return 0.15;
  if (value == "rtu")
    return 0.25;
  if (value == "hmi")
    return 0.35;
  if (value == "engineering_workstation")
    return 0.45;
  if (value == "historian")
    return 0.55;
  if (value == "safety_controller")
    return 0.65;
  return 0.95;
}

static double hourValue(const std::string &timestamp) {
  if (timestamp.size() >= 13) {
    try {
      return std::stoi(timestamp.substr(11, 2)) / 23.0;
    } catch (...) {
      return 0.0;
    }
  }
  return 0.0;
}

LSTMDetector::LSTMDetector() : modelLoaded_(false) {
#ifdef USE_LIBTORCH
  torchModule_ = nullptr;
#endif
}

LSTMDetector::~LSTMDetector() {
#ifdef USE_LIBTORCH
  if (torchModule_ != nullptr) {
    delete static_cast<torch::jit::script::Module *>(torchModule_);
    torchModule_ = nullptr;
  }
#endif
}

bool LSTMDetector::loadModel(const std::string &modelPath) {
  flowWindows_.clear();
  featureDimSet_ = false;
  modelLoaded_ = false;
  simulated_ = modelPath == "simulated";
  modelPath_ = modelPath;
  if (modelPath.empty()) {
    return false;
  }

  if (simulated_) {
    std::cout << "[LSTMDetector] Running LSTM/Autoencoder in simulated mode.\n";
    modelLoaded_ = true;
    return true;
  }

#ifdef USE_LIBTORCH
  try {
    at::set_num_threads(1);
    std::ifstream metadataFile(modelPath + ".json");
    if (metadataFile) {
      const auto metadata = nlohmann::json::parse(metadataFile);
      windowSize_ = metadata.at("window_size").get<int>();
      featureDim_ = metadata.at("feature_count").get<int>();
      anomalyThreshold_ = metadata.value("anomaly_threshold", 0.003);
      if (windowSize_ < 1 || featureDim_ < 7 || anomalyThreshold_ <= 0)
        throw std::runtime_error("Invalid model metadata");
      featureDimSet_ = true;
    }
    auto *module = new torch::jit::script::Module();
    try { *module = torch::jit::load(modelPath, torch::kCPU); }
    catch (...) { delete module; throw; }
    module->eval();
    delete static_cast<torch::jit::script::Module *>(torchModule_);
    torchModule_ = module;
    modelLoaded_ = true;
    std::cout << "[LSTMDetector] Loaded TorchScript model from: " << modelPath
              << "\n";
    return true;
  } catch (const std::exception &e) {
    std::cerr << "[LSTMDetector] Failed to load LibTorch model: " << e.what()
              << "\n";
    modelLoaded_ = false;
    return false;
  }
#else
  std::cerr << "[LSTMDetector] Real model requires a USE_LIBTORCH build. "
               "Use --lstm simulated explicitly for a lab proxy.\n";
  return false;
#endif
}

std::vector<double> LSTMDetector::extractFeatures(const Event &event) const {
  std::vector<double> features = {
      hashUnit(event.srcIp),
      hashUnit(event.dstIp),
      protocolCode(event.protocol),
      std::max(0.0,
               std::min(1.0, static_cast<double>(event.functionCode) / 255.0)),
      assetCode(event.assetRole),
      std::min(1.0, std::log1p(static_cast<double>(std::max(0, event.bytes))) /
                        std::log(2000000.0)),
      hourValue(event.timestamp)};

  // Append process-level extra features (already normalized to [0,1] by
  // the dataset normalizer, e.g. PipelinePSI, SetPoint, deltas)
  for (double v : event.extraFeatures) {
    features.push_back(v);
  }
  return features;
}

std::vector<Detection> LSTMDetector::evaluate(const Event &event) {
  lastError_.reset();
  std::vector<Detection> detections;
  if (!modelLoaded_) {
    return detections;
  }

  const auto currentFeatures = extractFeatures(event);

  // Dynamically set featureDim_ from the first event we see
  if (!featureDimSet_) {
    featureDim_ = static_cast<int>(currentFeatures.size());
    featureDimSet_ = true;
  }
  if (currentFeatures.size() != static_cast<std::size_t>(featureDim_))
    throw std::runtime_error("LSTM event feature dimensions do not match model");

  auto &window = flowWindows_[event.srcIp];

  // Add current event features to the sliding window
  window.push_back(currentFeatures);
  if (window.size() > static_cast<size_t>(windowSize_)) {
    window.pop_front();
  }

  // Model expects a full window sequence to make accurate predictions
  if (window.size() < static_cast<size_t>(windowSize_)) {
    return detections;
  }

  double reconstructionError = 0.0;

#ifdef USE_LIBTORCH
  if (torchModule_ != nullptr) {
    c10::InferenceMode inferenceGuard;
    auto *module = static_cast<torch::jit::script::Module *>(torchModule_);

    // 1. Flatten window features
    std::vector<float> flatFeatures;
    flatFeatures.reserve(windowSize_ * featureDim_);
    for (const auto &step : window) {
      for (double val : step) {
        flatFeatures.push_back(static_cast<float>(val));
      }
    }

    // 2. Create PyTorch Tensor [1, WindowSize, FeatureDim]
    auto options = torch::TensorOptions().dtype(torch::kFloat32);
    auto inputTensor = torch::from_blob(flatFeatures.data(),
                                        {1, windowSize_, featureDim_}, options)
                           .clone();

    // 3. Inference forward pass
    try {
      std::vector<torch::jit::IValue> inputs{inputTensor};
      auto outputTensor = module->forward(inputs).toTensor();

      // 4. Calculate Mean Squared Error (MSE) reconstruction loss
      if (inputTensor.sizes() != outputTensor.sizes())
        throw std::runtime_error("Model output shape must match event window");
      auto loss = (inputTensor - outputTensor).square().mean();
      reconstructionError = loss.item<double>();
    } catch (const std::exception &e) {
      throw std::runtime_error(std::string("LSTM inference failed: ") + e.what());
    }
  }
#endif
  if (simulated_) {
  // Simulated Reconstruction Error proxy
  // Calculate variance of the features in the window
  // High variance in protocol/function codes in a short window represents an
  // anomaly in OT cycles
  double varianceSum = 0.0;
  for (int d = 0; d < featureDim_; ++d) {
    double sum = 0.0;
    for (const auto &step : window) {
      sum += step[d];
    }
    double mean = sum / windowSize_;
    double sqSum = 0.0;
    for (const auto &step : window) {
      sqSum += (step[d] - mean) * (step[d] - mean);
    }
    varianceSum += (sqSum / windowSize_);
  }

  // Normalize proxy error to threshold range
  reconstructionError = std::min(0.95, varianceSum * 1.5);
  }
  lastError_ = reconstructionError;

  // Flag anomalies
  if (reconstructionError >= anomalyThreshold_) {
    std::string severity = "medium";
    if (reconstructionError >= 0.03) {
      severity = "critical";
    } else if (reconstructionError >= 0.01) {
      severity = "high";
    }

    double ratio = reconstructionError / anomalyThreshold_;
    double confidence = std::min(0.95, 0.5 + 0.05 * ratio);

    detections.push_back({event.id, "lstm_autoencoder",
                          "loss:" + std::to_string(reconstructionError),
                          severity,
                          "Anomaly Detection",
                          "LSTM Autoencoder reconstruction error exceeded "
                          "normal threshold (MSE=" +
                              std::to_string(reconstructionError) + ").",
                          confidence});
  }

  return detections;
}

} // namespace threatfusion

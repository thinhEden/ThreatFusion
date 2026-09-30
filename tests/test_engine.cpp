#include "threatfusion/BehaviorDetector.h"
#include "threatfusion/Csv.h"
#include "threatfusion/DataIngestion.h"
#include "threatfusion/OtContext.h"
#include "threatfusion/LSTMDetector.h"
#include "threatfusion/RiskScorer.h"
#include "threatfusion/SocketReceiver.h"
#include "threatfusion/ThreatIntel.h"

#include <cassert>
#include <cstdio>
#include <fstream>

using namespace threatfusion;

int main() {
  const auto row = parseCsvLine("a,\"b,c\",\"d\"\"e\"");
  assert(row.size() == 3);
  assert(row[1] == "b,c");
  assert(row[2] == "d\"e");

  const auto parsed = parseJsonEvent(R"({"id":"json-1","payload_path":"C:\\lab\\file\"name.bin","extra_features":[0.25,-2,1e-3]})");
  assert(parsed.extraFeatures.size() == 3);
  assert(parsed.extraFeatures[1] == -2.0);
  assert(parsed.payloadPath == "C:\\lab\\file\"name.bin");
  bool invalidJson = false;
  try { parseJsonEvent(R"({"id":"bad","extra_features":["oops"]})"); }
  catch (...) { invalidJson = true; }
  assert(invalidJson);
  invalidJson = false;
  try { parseJsonEvent(R"({"id":"bad","unit_id":1.5,"register_values":[55.5]})"); }
  catch (...) { invalidJson = true; }
  assert(invalidJson);

  const auto rulesPath = "test_rules.csv";
  writeCsv(rulesPath,
           {"id", "name", "severity", "tactic", "conditions", "description"},
           {{"R1", "Write to PLC", "high", "Impact",
             "protocol=modbus;function_code in 5|6|15|16;asset_role=plc",
             "write command"}});

  BehaviorDetector detector;
  assert(detector.loadRules(rulesPath));

  Event event;
  event.id = "E1";
  event.protocol = "modbus";
  event.functionCode = 16;
  event.assetRole = "plc";

  const auto detections = detector.evaluate(event);
  assert(detections.size() == 1);
  assert(detections[0].indicator == "R1");

  RiskScorer scorer;
  const auto alert = scorer.score(event, detections);
  assert(alert.riskScore >= 60);
  assert(alert.verdict == "critical" || alert.verdict == "malicious");

  std::remove(rulesPath);

  {
    const char* policy = "test_context.json";
    std::ofstream config(policy);
    config << R"({"authorizations":[{"ticket_id":"CHG-1","source_ip":"10.0.0.1","destination_ip":"10.0.0.2","unit_id":1,"function_codes":[6,16],"register_start":100,"register_end":101,"value_min":50,"value_max":60,"start_utc":"2026-09-30T10:00:00Z","end_utc":"2026-09-30T10:10:00Z","max_commands":2}]})";
    config.close();
    OtContext context;
    context.load(policy);
    Event write;
    write.protocol = "modbus"; write.isRequest = true; write.srcIp = "10.0.0.1"; write.dstIp = "10.0.0.2";
    write.timestamp = "2026-09-30T10:01:00Z"; write.unitId = 1; write.functionCode = 6;
    write.registerAddress = 100; write.registerCount = 1; write.registerValues = {55};
    const std::vector<Detection> candidate = {{"event", "behavior", "BR-001", "high", "Command Injection", "write", .8}};
    assert(context.apply(write, candidate).suppressed == 1);
    assert(context.apply(write, candidate).suppressed == 1);
    assert(context.apply(write, candidate).suppressed == 0);
    context.load(policy);
    write.unitId = 2; assert(context.apply(write, candidate).suppressed == 0); write.unitId = 1;
    write.registerAddress = 102; assert(context.apply(write, candidate).suppressed == 0); write.registerAddress = 100;
    write.registerValues = {900}; assert(context.apply(write, candidate).suppressed == 0); write.registerValues = {55};
    write.functionCode = 16; write.registerCount = 2; assert(context.apply(write, candidate).suppressed == 0);
    write.functionCode = 6; write.registerCount = 1;
    write.timestamp = "2026-09-30T10:10:00Z"; assert(context.apply(write, candidate).suppressed == 0);
    write.timestamp = "2026-09-30T10:01:00Z";
    auto corroborated = candidate;
    corroborated.push_back({"event", "threat_intel", "ioc", "critical", "IOC", "evidence", .95});
    assert(context.apply(write, corroborated).detections.size() == 2);
    write.label = "malicious";
    assert(context.apply(write, candidate).suppressed == 1); // Labels are never a context input.
    std::remove(policy);
  }

  // Test LSTMDetector
  {
    LSTMDetector lstm;
    // Verify loading simulated fallback mode
    assert(lstm.loadModel("simulated"));

    // Push 10 events to satisfy sliding window (W=10)
    std::vector<Detection> lstmDetections;
    for (int i = 0; i < 10; ++i) {
      Event ev;
      ev.srcIp = "192.168.1.100";
      ev.dstIp = "192.168.1.11";
      ev.protocol = "modbus";
      ev.functionCode = 3;
      ev.assetRole = "plc";
      ev.bytes = 100 + i * 10;
      ev.timestamp = "2015-12-22T16:00:00Z";

      lstmDetections = lstm.evaluate(ev);
    }
    printf("[TEST] LSTMDetector evaluated successfully.\n");
  }

  // Test SocketReceiver
  {
    SocketReceiver receiver;
    auto dummyCallback = [](const Event &event) {};
    assert(receiver.start(8089, dummyCallback));
    receiver.stop();
    printf("[TEST] SocketReceiver started and stopped successfully.\n");
  }

  printf("[TEST] All ThreatFusion-AI tests passed successfully!\n");
  return 0;
}

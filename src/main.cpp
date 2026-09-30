#include "threatfusion/AttackMapping.h"
#include "threatfusion/BaselineDetector.h"
#include "threatfusion/BehaviorDetector.h"
#include "threatfusion/Csv.h"
#include "threatfusion/DataIngestion.h"
#include "threatfusion/Evaluator.h"
#include "threatfusion/ExternalScanner.h"
#include "threatfusion/IncidentAggregator.h"
#include "threatfusion/IsolationForestDetector.h"
#include "threatfusion/LSTMDetector.h"
#include "threatfusion/RiskScorer.h"
#include "threatfusion/SocketReceiver.h"
#include "threatfusion/ThreatIntel.h"
#include "threatfusion/OtContext.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>
#include <iomanip>
#include <sstream>

using namespace threatfusion;

static std::string precise(double value) {
  std::ostringstream stream;
  stream << std::setprecision(17) << value;
  return stream.str();
}

struct Options {
  std::string mode = "batch";
  int port = 8080;
  std::string lstmPath;
  std::string eventsPath = "data/sample_ot_events.csv";
  std::string inputFormat = "csv";
  std::string tsharkPath = "tshark";
  std::string baselinePath;
  std::string baselineFormat = "csv";
  std::string iocsPath = "data/iocs.csv";
  std::string rulesPath = "data/behavior_rules.csv";
  std::string yaraPath;
  std::string yaraRulesPath;
  std::string snortPath;
  std::string snortConfigPath;
  std::string suricataPath;
  std::string suricataRulesPath;
  std::string suricataLogDir = "out/suricata";
  std::string alertsPath = "out/alerts.csv";
  std::string incidentsPath = "out/incidents.csv";
  std::string metricsPath = "out/metrics.txt";
  std::string scoresPath;
  std::string timingsPath;
  std::string attackMapPath = "data/attack_mapping.csv";
  bool attackMapRequired = false;
  std::string contextPath;
  std::string hostAlertsPath;
  double hostAlertWindow = 3600;
  std::string contextMode = "bounded";
  std::string contextAuditPath = "out/context_audit.csv";
  std::string normalizedEventsPath;
  std::string pcapFilter;
  std::string statsPath;
  double statsInterval = 1.0;
  unsigned ifSeed = 1337;
  double ifThreshold = 0.55;
  std::size_t lstmMaxFlows = 4096;
  int threshold = 60;
};

static void printUsage() {
  std::cout
      << "ThreatFusion AI - OT/ICS threat detection prototype\n"
      << "Usage: threatfusion [--mode batch|stream] [--port port] [--lstm "
         "path]\n"
      << "                    [--events path] [--format csv|jsonl|pcap] "
         "[--tshark path]\n"
      << "                    [--baseline path] [--baseline-format csv|jsonl]\n"
      << "                    [--iocs path] [--rules path] [--yara path "
         "--yara-rules path]\n"
      << "                    [--suricata path --suricata-rules path]\n"
      << "                    [--snort path --snort-config path]\n"
      << "                    [--alerts path] [--incidents path]\n"
      << "                    [--metrics path] [--threshold 60]\n";
  std::cout << "                    [--scores path] (raw IF/LSTM scores for research) [--if-seed 1337]\n";
  std::cout << "                    [--if-threshold 0.55] (uncalibrated default; set from benign validation data)\n";
  std::cout << "                    [--stats path --stats-interval 1] (stream counters for performance runs)\n";
  std::cout << "                    [--lstm-max-flows 4096] (per-source LSTM windows kept in memory)\n";
  std::cout << "                    [--context policy.json --context-audit path]\n"
               "                    [--context-mode bounded|peer-only] (peer-only is an unsafe ablation)\n"
               "                    [--normalized-events path] [--pcap-filter expression] [--timings path]\n"
               "                    [--host-alerts host_alerts.csv --host-alert-window 3600] (needs --context)\n"
               "                    [--attack-map data/attack_mapping.csv] (MITRE ATT&CK IDs per detection)\n";
}

static Options parseArgs(int argc, char **argv) {
  Options options;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    auto requireValue = [&](const std::string &name) -> std::string {
      if (i + 1 >= argc) {
        throw std::runtime_error("Missing value for " + name);
      }
      return argv[++i];
    };

    if (arg == "--mode")
      options.mode = requireValue(arg);
    else if (arg == "--port")
      options.port = std::stoi(requireValue(arg));
    else if (arg == "--lstm")
      options.lstmPath = requireValue(arg);
    else if (arg == "--lstm-max-flows")
      options.lstmMaxFlows = std::stoul(requireValue(arg));
    else if (arg == "--events")
      options.eventsPath = requireValue(arg);
    else if (arg == "--format")
      options.inputFormat = requireValue(arg);
    else if (arg == "--tshark")
      options.tsharkPath = requireValue(arg);
    else if (arg == "--baseline")
      options.baselinePath = requireValue(arg);
    else if (arg == "--baseline-format")
      options.baselineFormat = requireValue(arg);
    else if (arg == "--iocs")
      options.iocsPath = requireValue(arg);
    else if (arg == "--rules")
      options.rulesPath = requireValue(arg);
    else if (arg == "--yara")
      options.yaraPath = requireValue(arg);
    else if (arg == "--yara-rules")
      options.yaraRulesPath = requireValue(arg);
    else if (arg == "--snort")
      options.snortPath = requireValue(arg);
    else if (arg == "--snort-config")
      options.snortConfigPath = requireValue(arg);
    else if (arg == "--suricata")
      options.suricataPath = requireValue(arg);
    else if (arg == "--suricata-rules")
      options.suricataRulesPath = requireValue(arg);
    else if (arg == "--suricata-logdir")
      options.suricataLogDir = requireValue(arg);
    else if (arg == "--alerts")
      options.alertsPath = requireValue(arg);
    else if (arg == "--incidents")
      options.incidentsPath = requireValue(arg);
    else if (arg == "--metrics")
      options.metricsPath = requireValue(arg);
    else if (arg == "--scores")
      options.scoresPath = requireValue(arg);
    else if (arg == "--timings")
      options.timingsPath = requireValue(arg);
    else if (arg == "--attack-map") {
      options.attackMapPath = requireValue(arg);
      options.attackMapRequired = true;
    }
    else if (arg == "--context")
      options.contextPath = requireValue(arg);
    else if (arg == "--host-alerts")
      options.hostAlertsPath = requireValue(arg);
    else if (arg == "--host-alert-window")
      options.hostAlertWindow = std::stod(requireValue(arg));
    else if (arg == "--context-mode")
      options.contextMode = requireValue(arg);
    else if (arg == "--context-audit")
      options.contextAuditPath = requireValue(arg);
    else if (arg == "--normalized-events")
      options.normalizedEventsPath = requireValue(arg);
    else if (arg == "--pcap-filter")
      options.pcapFilter = requireValue(arg);
    else if (arg == "--threshold")
      options.threshold = std::stoi(requireValue(arg));
    else if (arg == "--stats")
      options.statsPath = requireValue(arg);
    else if (arg == "--stats-interval")
      options.statsInterval = std::stod(requireValue(arg));
    else if (arg == "--if-seed")
      options.ifSeed = static_cast<unsigned>(std::stoul(requireValue(arg)));
    else if (arg == "--if-threshold")
      options.ifThreshold = std::stod(requireValue(arg));
    else if (arg == "--help" || arg == "-h") {
      printUsage();
      std::exit(0);
    } else {
      throw std::runtime_error("Unknown argument: " + arg);
    }
  }
  options.mode = toLower(options.mode);
  if (options.mode != "batch" && options.mode != "stream") throw std::runtime_error("Unknown engine mode");
  if (options.mode == "stream" && (!options.timingsPath.empty() || !options.normalizedEventsPath.empty()))
    throw std::runtime_error("--timings and --normalized-events are batch-only exports");
  if (!options.hostAlertsPath.empty() && options.contextPath.empty())
    throw std::runtime_error("--host-alerts requires --context");
  if (!options.statsPath.empty() && options.mode != "stream")
    throw std::runtime_error("--stats is a stream-mode export; batch mode has --timings");
  if (!(options.statsInterval > 0)) throw std::runtime_error("--stats-interval must be positive");
  return options;
}

int main(int argc, char **argv) {
  std::ios::sync_with_stdio(false);
  std::cin.tie(nullptr);
  try {
    const auto options = parseArgs(argc, argv);

    ThreatIntel threatIntel;
    threatIntel.loadIocs(options.iocsPath);

    BehaviorDetector detector;
    detector.loadRules(options.rulesPath);

    AttackMapping attackMapping;
    if (std::ifstream(options.attackMapPath)) attackMapping.load(options.attackMapPath);
    else if (options.attackMapRequired) throw std::runtime_error("Cannot open ATT&CK mapping: " + options.attackMapPath);
    auto annotate = [&](std::vector<Detection>& detections) {
      for (auto& detection : detections) detection.attack = attackMapping.lookup(detection);
    };

    OtContext context;
    std::vector<std::vector<std::string>> contextAuditRows;
    std::ofstream contextAuditStream;
    const std::vector<std::string> auditHeaders = {"event_id", "timestamp", "policy_id", "raw_detections", "retained_detections", "suppressed_detections", "reason"};
    if (!options.contextPath.empty()) {
      if (options.contextMode != "bounded" && options.contextMode != "peer-only")
        throw std::runtime_error("Unknown context mode");
      context.load(options.contextPath, options.contextMode == "peer-only");
      if (!options.hostAlertsPath.empty()) context.loadHostAlerts(options.hostAlertsPath, options.hostAlertWindow);
      writeCsv(options.contextAuditPath, auditHeaders, {});
      if (options.mode == "stream") contextAuditStream.open(options.contextAuditPath, std::ios::app);
    }
    auto applyContext = [&](const Event& event, std::vector<Detection>& detections) {
      if (options.contextPath.empty()) return;
      auto decision = context.apply(event, detections);
      std::vector<std::string> row = {event.id, event.timestamp, decision.policyId, std::to_string(detections.size()),
         std::to_string(decision.detections.size()), std::to_string(decision.suppressed), decision.reason};
      if (options.mode == "stream") { writeCsvRow(contextAuditStream, row); contextAuditStream.flush(); }
      else contextAuditRows.push_back(std::move(row));
      detections = std::move(decision.detections);
    };

    BaselineDetector baselineDetector;
    IsolationForestDetector isolationForestDetector;
    if (!options.baselinePath.empty()) {
      IngestionOptions baselineOptions;
      baselineOptions.format = options.baselineFormat;
      baselineOptions.tsharkPath = options.tsharkPath;
      const auto baselineEvents =
          loadEvents(options.baselinePath, baselineOptions);
      baselineDetector.train(baselineEvents);
      isolationForestDetector.train(baselineEvents, 100, 8, options.ifSeed);
      isolationForestDetector.setThreshold(options.ifThreshold);
    }

    LSTMDetector lstmDetector;
    lstmDetector.setMaxFlows(options.lstmMaxFlows);
    if (!options.lstmPath.empty()) {
      if (!lstmDetector.loadModel(options.lstmPath))
        throw std::runtime_error("LSTM model could not be loaded");
    }

    ExternalScanner externalScanner;
    if (!options.yaraPath.empty() && !options.yaraRulesPath.empty()) {
      externalScanner.setYara(options.yaraPath, options.yaraRulesPath);
    }
    if (!options.snortPath.empty() && !options.snortConfigPath.empty() &&
        toLower(options.inputFormat) == "pcap") {
      externalScanner.setSnort(options.snortPath, options.snortConfigPath,
                               options.eventsPath);
    }
    if (!options.suricataPath.empty() && !options.suricataRulesPath.empty() &&
        toLower(options.inputFormat) == "pcap") {
      externalScanner.setSuricata(options.suricataPath,
                                  options.suricataRulesPath, options.eventsPath,
                                  options.suricataLogDir);
    }

    if (toLower(options.mode) == "stream") {
      SocketReceiver receiver;
      RiskScorer scorer;
      // Counters for --stats. Detection time covers detectors, context and risk scoring, not alert output.
      std::atomic<long long> streamEvents{0}, streamAlerts{0}, detectNsTotal{0}, detectNsMax{0};
      auto record = [&](std::chrono::steady_clock::time_point start, bool alerted) {
        const long long ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - start).count();
        detectNsTotal += ns;
        long long seen = detectNsMax.load();
        while (ns > seen && !detectNsMax.compare_exchange_weak(seen, ns)) {}
        if (alerted) ++streamAlerts;
        ++streamEvents;
      };
      // Opened once: reopening per alert (header check, open, close) dominated stream time on Windows.
      auto streamAlertLog = openCsvAppend("out/alerts_stream.csv",
          {"incident_id", "event_id", "timestamp", "src_ip", "dst_ip", "asset_role",
           "protocol", "classification", "top_severity", "asset_criticality",
           "threat_severity", "confidence_score", "risk_score", "latency_ms", "verdict", "reasons",
           "attack_techniques"});
      std::mutex statsMutex;
      std::condition_variable statsWake;
      bool statsStop = false;
      std::thread statsThread;
      auto callback = [&](const Event &event) {
        const auto detectionStart = std::chrono::steady_clock::now();
        auto detections = threatIntel.correlate(event);
        auto behavioral = detector.evaluate(event);
        detections.insert(detections.end(), behavioral.begin(),
                          behavioral.end());
        auto baseline = baselineDetector.evaluate(event);
        detections.insert(detections.end(), baseline.begin(), baseline.end());
        auto isolationForest = isolationForestDetector.evaluate(event);
        detections.insert(detections.end(), isolationForest.begin(),
                          isolationForest.end());
        auto lstm = lstmDetector.evaluate(event);
        detections.insert(detections.end(), lstm.begin(), lstm.end());
        auto external = externalScanner.evaluate(event);
        detections.insert(detections.end(), external.begin(), external.end());

        applyContext(event, detections);
        annotate(detections);

        if (detections.empty()) {
          record(detectionStart, false);
          return;
        }

        auto alert = scorer.score(event, detections);
        const auto detectionEnd = std::chrono::steady_clock::now();
        alert.latencyMs = std::chrono::duration<double, std::milli>(
                              detectionEnd - detectionStart)
                              .count();
        record(detectionStart, true);

        std::cout << "[ALERT] Event: " << alert.eventId
                  << " | IP: " << alert.srcIp << " -> " << alert.dstIp
                  << " | Protocol: " << alert.protocol
                  << " | Risk Score: " << alert.riskScore
                  << " | Verdict: " << alert.verdict
                  << " | Reasons: " << alert.reasons << "\n";

        writeCsvRow(streamAlertLog,
          {alert.incidentId, alert.eventId, alert.timestamp, alert.srcIp, alert.dstIp,
           alert.assetRole, alert.protocol, alert.classification, alert.topSeverity,
           precise(alert.assetCriticality), precise(alert.threatSeverity),
           precise(alert.confidenceScore), std::to_string(alert.riskScore),
           precise(alert.latencyMs), alert.verdict, alert.reasons, alert.attack});
        // Flushed per alert because the dashboard tails this file.
        streamAlertLog.flush();
      };

      if (!receiver.start(options.port, callback)) {
        std::cerr << "Failed to start socket receiver on port " << options.port
                  << "\n";
        return 1;
      }
      if (!options.statsPath.empty()) {
        writeCsv(options.statsPath, {"unix_ms", "elapsed_s", "events", "alerts", "detect_ms_total", "detect_ms_max_interval"}, {});
        statsThread = std::thread([&] {
          std::ofstream stats(options.statsPath, std::ios::app);
          const auto started = std::chrono::steady_clock::now();
          const std::chrono::duration<double> interval(options.statsInterval);
          std::unique_lock<std::mutex> lock(statsMutex);
          for (bool last = false; !last;) {
            last = statsWake.wait_for(lock, interval, [&] { return statsStop; });
            const auto unixMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            stats << unixMs << ',' << precise(std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count())
                  << ',' << streamEvents.load() << ',' << streamAlerts.load() << ',' << precise(detectNsTotal.load() / 1e6)
                  << ',' << precise(detectNsMax.exchange(0) / 1e6) << '\n';
            stats.flush();
          }
        });
      }

      std::cout << "ThreatFusion Engine running in STREAMING mode on port "
                << options.port << "\n";
      std::cout << "Press Enter to stop the engine...\n";
      std::cin.get();
      receiver.stop();
      if (statsThread.joinable()) {
        {
          std::lock_guard<std::mutex> lock(statsMutex);
          statsStop = true;
        }
        statsWake.notify_one();
        statsThread.join();
      }
      return 0;
    }

    IngestionOptions ingestionOptions;
    ingestionOptions.format = options.inputFormat;
    ingestionOptions.tsharkPath = options.tsharkPath;
    ingestionOptions.pcapFilter = options.pcapFilter;
    const auto events = loadEvents(options.eventsPath, ingestionOptions);
    if (!options.normalizedEventsPath.empty()) {
      ensureParentDirectory(options.normalizedEventsPath);
      std::ofstream normalizedFile(options.normalizedEventsPath);
      if (!normalizedFile) throw std::runtime_error("Cannot write normalized events");
      for (const auto& event : events) normalizedFile << eventJson(event) << '\n';
    }

    RiskScorer scorer;
    std::vector<Alert> alerts;
    std::vector<std::vector<std::string>> scoreRows;
    std::vector<std::vector<std::string>> timingRows;

    for (const auto &event : events) {
      const auto detectionStart = std::chrono::steady_clock::now();
      auto detections = threatIntel.correlate(event);
      auto behavioral = detector.evaluate(event);
      detections.insert(detections.end(), behavioral.begin(), behavioral.end());
      auto baseline = baselineDetector.evaluate(event);
      detections.insert(detections.end(), baseline.begin(), baseline.end());
      auto isolationForest = isolationForestDetector.evaluate(event);
      detections.insert(detections.end(), isolationForest.begin(),
                        isolationForest.end());
      auto lstm = lstmDetector.evaluate(event);
      detections.insert(detections.end(), lstm.begin(), lstm.end());
      auto external = externalScanner.evaluate(event);
      detections.insert(detections.end(), external.begin(), external.end());

      applyContext(event, detections);
      annotate(detections);

      if (!options.scoresPath.empty()) {
        const auto error = lstmDetector.lastError();
        scoreRows.push_back({event.id, event.label,
          precise(isolationForestDetector.anomalyScore(event)),
          error ? precise(*error) : ""});
      }
      if (detections.empty()) {
        if (!options.timingsPath.empty()) timingRows.push_back({event.id,
          precise(std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - detectionStart).count())});
        continue;
      }

      auto alert = scorer.score(event, detections);
      const auto detectionEnd = std::chrono::steady_clock::now();
      alert.latencyMs = std::chrono::duration<double, std::milli>(
                            detectionEnd - detectionStart)
                            .count();
      if (!options.timingsPath.empty()) timingRows.push_back({event.id, precise(alert.latencyMs)});
      alerts.push_back(alert);
    }

    for (const auto &detection : externalScanner.evaluatePcap()) {
      Event event;
      event.id = detection.eventId;
      event.timestamp =
          detection.timestamp.empty() ? "pcap" : detection.timestamp;
      event.srcIp = detection.srcIp;
      event.dstIp = detection.dstIp;
      event.assetRole =
          detection.assetRole.empty() ? "network" : detection.assetRole;
      event.protocol = detection.protocol.empty() ? "pcap" : detection.protocol;
      std::vector<Detection> external = {detection};
      annotate(external);
      auto alert = scorer.score(event, external);
      alert.latencyMs = 0.0;
      alerts.push_back(alert);
    }

    const auto incidents = aggregateIncidents(alerts);
    if (!options.contextPath.empty()) writeCsv(options.contextAuditPath, auditHeaders, contextAuditRows);
    if (!options.timingsPath.empty()) writeCsv(options.timingsPath, {"event_id", "processing_ms"}, timingRows);
    if (!options.scoresPath.empty())
      writeCsv(options.scoresPath, {"event_id", "label", "if_score", "lstm_error"}, scoreRows);

    std::map<std::string, Alert> alertsByEventId;
    std::vector<std::vector<std::string>> alertRows;
    for (const auto &alert : alerts) {
      alertsByEventId[alert.eventId] = alert;
      alertRows.push_back(
          {alert.incidentId, alert.eventId, alert.timestamp, alert.srcIp,
           alert.dstIp, alert.assetRole, alert.protocol, alert.classification,
           alert.topSeverity, std::to_string(alert.assetCriticality),
           std::to_string(alert.threatSeverity),
           std::to_string(alert.confidenceScore),
           std::to_string(alert.riskScore), std::to_string(alert.latencyMs),
           alert.verdict, alert.reasons, alert.attack});
    }

    writeCsv(options.alertsPath,
             {"incident_id", "event_id", "timestamp", "src_ip", "dst_ip",
              "asset_role", "protocol", "classification", "top_severity",
              "asset_criticality", "threat_severity", "confidence_score",
              "risk_score", "latency_ms", "verdict", "reasons", "attack_techniques"},
             alertRows);

    std::vector<std::vector<std::string>> incidentRows;
    for (const auto &incident : incidents) {
      incidentRows.push_back(
          {incident.id, incident.firstSeen, incident.lastSeen,
           incident.classification, incident.topSeverity,
           std::to_string(incident.maxRiskScore),
           std::to_string(incident.alertCount), incident.srcIp, incident.dstIp,
           incident.affectedAssets, incident.eventIds});
    }
    writeCsv(options.incidentsPath,
             {"incident_id", "first_seen", "last_seen", "classification",
              "top_severity", "max_risk_score", "alert_count", "src_ip",
              "dst_ip", "affected_assets", "event_ids"},
             incidentRows);

    const auto metrics =
        evaluateMetrics(events, alertsByEventId, options.threshold);
    const auto metricsText = formatMetrics(metrics);
    ensureParentDirectory(options.metricsPath);
    std::ofstream metricsFile(options.metricsPath);
    metricsFile << metricsText;

    std::cout << "events=" << events.size() << '\n';
    std::cout << "alerts=" << alertRows.size() << '\n';
    std::cout << "incidents=" << incidents.size() << '\n';
    std::cout << metricsText;
    std::cout << "alerts_path=" << options.alertsPath << '\n';
    std::cout << "incidents_path=" << options.incidentsPath << '\n';
    std::cout << "metrics_path=" << options.metricsPath << '\n';
    return 0;
  } catch (const std::exception &ex) {
    std::cerr << "error: " << ex.what() << '\n';
    return 1;
  }
}

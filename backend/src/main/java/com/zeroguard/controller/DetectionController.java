package com.zeroguard.controller;

import com.zeroguard.model.Alert;
import com.zeroguard.model.DetectionResult;
import com.zeroguard.model.PacketModel;
import com.zeroguard.service.TrafficStreamerService;
import com.zeroguard.service.ZeroDayDetectionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class DetectionController {

    @Autowired
    private ZeroDayDetectionService detectionService;

    @Autowired
    private TrafficStreamerService streamerService;

    @PostMapping("/stream/start")
    public ResponseEntity<Map<String, String>> startStream() {
        streamerService.startStreaming();
        Map<String, String> response = new HashMap<>();
        response.put("status", "success");
        response.put("message", "Traffic stream initiated.");
        response.put("timestamp", java.time.Instant.now().toString());
        return ResponseEntity.ok(response);
    }
    
    @PostMapping("/stream/stop")
    public ResponseEntity<Map<String, String>> stopStream() {
        streamerService.stopStreaming();
        Map<String, String> response = new HashMap<>();
        response.put("status", "success");
        response.put("message", "Traffic stream stopped.");
        response.put("timestamp", java.time.Instant.now().toString());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/stream/inject")
    public ResponseEntity<Map<String, String>> injectAttack(@RequestBody(required = false) Map<String, Object> payload) {
        if (payload == null) payload = new HashMap<>();
        streamerService.injectZeroDayAttack(payload);
        Map<String, String> response = new HashMap<>();
        response.put("status", "success");
        return ResponseEntity.ok(response);
    }

    @PostMapping("/config/threshold")
    public ResponseEntity<Map<String, String>> updateThreshold(@RequestBody Map<String, Double> payload) {
        if (payload != null && payload.containsKey("threshold")) {
            detectionService.setConfidenceThreshold(payload.get("threshold"));
        }
        Map<String, String> response = new HashMap<>();
        response.put("status", "success");
        return ResponseEntity.ok(response);
    }

    @PostMapping("/packet/analyze")
    public ResponseEntity<DetectionResult> analyzePacket(@RequestBody PacketModel packet) {
        DetectionResult result = detectionService.analyzePacket(packet);
        return ResponseEntity.ok(result);
    }

    @GetMapping("/alerts")
    public ResponseEntity<List<Alert>> getAlerts() {
        return ResponseEntity.ok(streamerService.getAlerts());
    }
}

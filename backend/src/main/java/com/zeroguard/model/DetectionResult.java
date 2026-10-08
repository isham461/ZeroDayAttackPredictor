package com.zeroguard.model;

import lombok.Data;
import java.util.List;

@Data
public class DetectionResult {
    private String packetId;
    private double anomalyScore;
    private boolean isAnomaly;
    private String classification;
    private double confidenceScore;
    private List<String> triggeringFeatures;
}

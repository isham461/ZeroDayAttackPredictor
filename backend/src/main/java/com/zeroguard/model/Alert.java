package com.zeroguard.model;

import lombok.Data;

@Data
public class Alert {
    private String alertId;
    private String timestamp;
    private String packetId;
    private String severity;
    private String type;
    private String details;
}

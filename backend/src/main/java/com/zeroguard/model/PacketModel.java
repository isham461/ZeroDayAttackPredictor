package com.zeroguard.model;

import lombok.Data;

@Data
public class PacketModel {
    private String packetId;
    private String protocol;
    private String sourceIp;
    private String destinationIp;
    private double duration;
    private int packetSize;
    private double errorRate;
    private String flag;
}

package com.zeroguard.service;

import com.zeroguard.model.PacketModel;
import com.zeroguard.model.DetectionResult;
import org.springframework.stereotype.Service;
import weka.classifiers.trees.RandomForest;
import weka.core.Attribute;
import weka.core.DenseInstance;
import weka.core.Instances;
import jakarta.annotation.PostConstruct;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

@Service
public class ZeroDayDetectionService {

    private RandomForest randomForest;
    private Instances datasetStructure;
    private Random random = new Random();
    private double confidenceThreshold = 0.70;

    public void setConfidenceThreshold(double threshold) {
        this.confidenceThreshold = threshold;
    }

    @PostConstruct
    public void initModels() {
        try {
            // Stage 1: Setup attributes for Weka
            ArrayList<Attribute> attributes = new ArrayList<>();
            attributes.add(new Attribute("duration"));
            attributes.add(new Attribute("packetSize"));
            attributes.add(new Attribute("errorRate"));

            // Stage 2: Classifier classes
            ArrayList<String> classValues = new ArrayList<>();
            classValues.add("Normal");
            classValues.add("DDoS");
            classValues.add("PortScan");
            Attribute classAttribute = new Attribute("class", classValues);
            attributes.add(classAttribute);

            datasetStructure = new Instances("NetworkTraffic", attributes, 0);
            datasetStructure.setClassIndex(datasetStructure.numAttributes() - 1);

            // Generate synthetic baseline data to initialize the models
            Instances baselineData = new Instances(datasetStructure, 200);
            for (int i = 0; i < 200; i++) {
                double[] values = new double[datasetStructure.numAttributes()];
                values[0] = random.nextDouble() * 5; // duration
                values[1] = random.nextInt(1200);   // packetSize
                values[2] = random.nextDouble() * 0.05; // errorRate
                values[3] = random.nextInt(3); // class
                baselineData.add(new DenseInstance(1.0, values));
            }


            // Train Random Forest
            randomForest = new RandomForest();
            randomForest.buildClassifier(baselineData);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public DetectionResult analyzePacket(PacketModel packet) {
        DetectionResult result = new DetectionResult();
        result.setPacketId(packet.getPacketId());

        try {
            double[] values = new double[datasetStructure.numAttributes()];
            values[0] = packet.getDuration();
            values[1] = packet.getPacketSize();
            values[2] = packet.getErrorRate();
            values[3] = 0; 

            DenseInstance instance = new DenseInstance(1.0, values);
            instance.setDataset(datasetStructure);

            // Determine if it's an anomaly (Simulation logic since actual IF in weka can be tricky to extract precise score)
            // Simulating anomaly if size > 1400 or errorRate > 0.8 to create realistic zero-day scenarios
            boolean simulatedAnomaly = packet.getPacketSize() > 1400 || packet.getErrorRate() > 0.8;
            result.setAnomaly(simulatedAnomaly);
            result.setAnomalyScore(simulatedAnomaly ? 0.85 + (random.nextDouble() * 0.1) : 0.1 + (random.nextDouble() * 0.2));

            // Stage 2: Supervised Random Forest Classification
            double[] classDist = randomForest.distributionForInstance(instance);
            int maxIndex = 0;
            double maxConfidence = classDist[0];
            for (int i = 1; i < classDist.length; i++) {
                if (classDist[i] > maxConfidence) {
                    maxConfidence = classDist[i];
                    maxIndex = i;
                }
            }

            // Zero-Day Logic: Anomaly detected, but classifier confidence is low
            if (result.isAnomaly()) {
                if (maxConfidence < confidenceThreshold) {
                    result.setClassification("Novel Zero-Day Attack");
                    result.setConfidenceScore(maxConfidence);
                } else {
                    result.setClassification(datasetStructure.classAttribute().value(maxIndex));
                    result.setConfidenceScore(maxConfidence);
                }
            } else {
                result.setClassification("Normal Traffic");
                result.setConfidenceScore(maxConfidence);
            }

            // Interpretability Layer: Flag triggering features
            List<String> triggers = new ArrayList<>();
            if (packet.getPacketSize() > 1400) triggers.add("packetSize");
            if (packet.getErrorRate() > 0.8) triggers.add("errorRate");
            if (packet.getDuration() > 4.5) triggers.add("duration");
            result.setTriggeringFeatures(triggers);

        } catch (Exception e) {
            e.printStackTrace();
            result.setClassification("Analysis Error");
        }

        return result;
    }
}

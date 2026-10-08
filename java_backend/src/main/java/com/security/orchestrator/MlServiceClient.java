package com.security.orchestrator;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Synchronous HTTP Client responsible for communicating with the Python FastAPI ML Microservice.
 */
public class MlServiceClient {
    private final String mlServiceBaseUrl;
    private final HttpClient httpClient;

    public MlServiceClient(String mlServiceBaseUrl) {
        this.mlServiceBaseUrl = mlServiceBaseUrl.replaceAll("/$", "");
        this.httpClient = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(5))
            .build();
    }

    /**
     * Probes the Python FastAPI /health endpoint.
     */
    public boolean checkHealth() {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(this.mlServiceBaseUrl + "/health"))
                .timeout(Duration.ofSeconds(3))
                .GET()
                .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            return response.statusCode() == 200;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Forwards network traffic payload to Python FastAPI /predict endpoint synchronously.
     *
     * @param jsonPayload The formatted JSON request payload.
     * @return Raw JSON response string from FastAPI.
     * @throws IOException If the Python microservice is unreachable.
     * @throws InterruptedException If the request is interrupted.
     */
    public String forwardPrediction(String jsonPayload) throws IOException, InterruptedException {
        String targetUrl = this.mlServiceBaseUrl + "/predict";
        
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(targetUrl))
            .timeout(Duration.ofSeconds(10))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
            .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        
        if (response.statusCode() >= 400) {
            throw new IOException("ML Service returned HTTP " + response.statusCode() + ": " + response.body());
        }

        return response.body();
    }
}

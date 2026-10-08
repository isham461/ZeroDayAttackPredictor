package com.security.orchestrator;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * HTTP Controller routing incoming frontend requests and managing communication with the ML engine.
 */
public class NetworkTrafficController implements HttpHandler {
    private final MlServiceClient mlClient;

    public NetworkTrafficController(MlServiceClient mlClient) {
        this.mlClient = mlClient;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String method = exchange.getRequestMethod();
        String path = exchange.getRequestURI().getPath();

        // 1. Handle CORS Preflight (OPTIONS)
        if ("OPTIONS".equalsIgnoreCase(method)) {
            sendCorsHeaders(exchange);
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
            return;
        }

        // 2. Dispatch Routes
        try {
            if ("GET".equalsIgnoreCase(method) && ("/api/health".equals(path) || "/health".equals(path))) {
                handleHealth(exchange);
            } else if ("GET".equalsIgnoreCase(method) && "/api/presets".equals(path)) {
                handlePresets(exchange);
            } else if ("POST".equalsIgnoreCase(method) && ("/api/analyze".equals(path) || "/api/logs".equals(path))) {
                handleAnalyze(exchange);
            } else {
                sendJsonResponse(exchange, 404, "{\"error\": \"Endpoint not found\", \"path\": \"" + path + "\"}");
            }
        } catch (Exception e) {
            System.err.println("[ERROR] Exception handling request " + path + ": " + e.getMessage());
            sendJsonResponse(exchange, 500, "{\"error\": \"Internal Server Error\", \"details\": \"" + escapeJson(e.getMessage()) + "\"}");
        }
    }

    /**
     * Health check endpoint: Probes Java Backend and Python FastAPI status.
     */
    private void handleHealth(HttpExchange exchange) throws IOException {
        boolean isMlHealthy = mlClient.checkHealth();
        String response = String.format(
            "{\"status\": \"UP\", \"service\": \"Java Security Orchestrator\", \"ml_service_connected\": %b, \"timestamp\": \"%s\"}",
            isMlHealthy, java.time.Instant.now().toString()
        );
        sendJsonResponse(exchange, 200, response);
    }

    /**
     * Serves sample dataset presets for instant 1-click frontend demonstrations.
     */
    private void handlePresets(HttpExchange exchange) throws IOException {
        File presetsFile = new File("models/sample_presets.json");
        if (presetsFile.exists()) {
            String content = Files.readString(presetsFile.toPath(), StandardCharsets.UTF_8);
            sendJsonResponse(exchange, 200, content);
        } else {
            sendJsonResponse(exchange, 200, "{}");
        }
    }

    /**
     * Receives network logs from frontend, invokes Python ML Engine synchronously,
     * logs audit event locally, and returns response.
     */
    private void handleAnalyze(HttpExchange exchange) throws IOException {
        String traceId = "TRC-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
        String clientIp = exchange.getRemoteAddress().getAddress().getHostAddress();
        long startTime = System.currentTimeMillis();

        // Read request body
        InputStream is = exchange.getRequestBody();
        String requestBody = new String(is.readAllBytes(), StandardCharsets.UTF_8);

        if (requestBody.trim().isEmpty()) {
            sendJsonResponse(exchange, 400, "{\"error\": \"Request body cannot be empty.\"}");
            return;
        }

        // Format payload: ensure wrapped in {"features": {...}} if not already
        String formattedPayload = formatPayloadForMlService(requestBody);

        try {
            // Synchronous HTTP POST to FastAPI
            String mlResponse = mlClient.forwardPrediction(formattedPayload);
            long latencyMs = System.currentTimeMillis() - startTime;

            // Extract quick summary tags for audit logging using regex
            String threatCategory = extractJsonString(mlResponse, "threat_category", "Unknown");
            String alertLevel = extractJsonString(mlResponse, "alert_level", "INFO");
            String verdict = extractJsonString(mlResponse, "verdict", "Evaluated");

            // Log event locally to disk & console
            SecurityAuditLogger.logEvent(traceId, clientIp, threatCategory, alertLevel, verdict, latencyMs);

            // Inject orchestration metadata into the response
            String enrichedResponse = mlResponse.substring(0, mlResponse.lastIndexOf("}")) +
                String.format(", \"trace_id\": \"%s\", \"orchestrator_latency_ms\": %d}", traceId, latencyMs);

            sendJsonResponse(exchange, 200, enrichedResponse);

        } catch (IOException e) {
            long latencyMs = System.currentTimeMillis() - startTime;
            System.err.println("[ERROR] Failed to reach Python ML Service: " + e.getMessage());
            SecurityAuditLogger.logEvent(traceId, clientIp, "Service Unavailable", "CRITICAL", "ML Engine Connection Failed", latencyMs);

            String errorJson = String.format(
                "{\"error\": \"ML Microservice Unreachable\", \"trace_id\": \"%s\", \"details\": \"%s\", \"hint\": \"Ensure Python FastAPI server is running on port 8000.\"}",
                traceId, escapeJson(e.getMessage())
            );
            sendJsonResponse(exchange, 503, errorJson);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            sendJsonResponse(exchange, 500, "{\"error\": \"Request processing interrupted.\"}");
        }
    }

    private String formatPayloadForMlService(String rawJson) {
        String trimmed = rawJson.trim();
        if (trimmed.contains("\"features\"")) {
            return trimmed;
        }
        // Wrap raw dictionary in {"features": ...}
        return "{\"features\": " + trimmed + "}";
    }

    private void sendCorsHeaders(HttpExchange exchange) {
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
    }

    private void sendJsonResponse(HttpExchange exchange, int statusCode, String responseJson) throws IOException {
        sendCorsHeaders(exchange);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        byte[] bytes = responseJson.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private String extractJsonString(String json, String key, String defaultVal) {
        Pattern pattern = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]+)\"");
        Matcher matcher = pattern.matcher(json);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return defaultVal;
    }

    private String escapeJson(String raw) {
        if (raw == null) return "";
        return raw.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "");
    }
}

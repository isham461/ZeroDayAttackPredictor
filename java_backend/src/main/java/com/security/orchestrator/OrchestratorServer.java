package com.security.orchestrator;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.Executors;

/**
 * Main Entry Point for the Java Security Orchestrator Backend.
 * Uses standard Java HTTP Server and HttpClient for high performance and zero external dependencies.
 */
public class OrchestratorServer {
    private static final int DEFAULT_PORT = 8080;
    private static final String DEFAULT_ML_URL = "http://localhost:8000";

    public static void main(String[] args) {
        int port = DEFAULT_PORT;
        String portEnv = System.getenv("PORT");
        if (portEnv != null && !portEnv.isEmpty()) {
            try {
                port = Integer.parseInt(portEnv);
            } catch (NumberFormatException ignored) {}
        }

        String mlUrl = System.getenv("ML_SERVICE_URL");
        if (mlUrl == null || mlUrl.isEmpty()) {
            mlUrl = DEFAULT_ML_URL;
        }

        System.out.println("===============================================================");
        System.out.println("   Java Security Orchestrator - Zero-Day Detection Engine     ");
        System.out.println("===============================================================");
        System.out.printf("  Orchestrator Port : http://localhost:%d\n", port);
        System.out.printf("  Python ML Service : %s\n", mlUrl);
        System.out.println("---------------------------------------------------------------");

        try {
            HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
            
            MlServiceClient mlClient = new MlServiceClient(mlUrl);
            NetworkTrafficController controller = new NetworkTrafficController(mlClient);

            // Register API endpoints
            server.createContext("/api/analyze", controller);
            server.createContext("/api/logs", controller);
            server.createContext("/api/health", controller);
            server.createContext("/api/presets", controller);
            server.createContext("/health", controller);

            // Configure multi-threaded executor pool
            server.setExecutor(Executors.newFixedThreadPool(16));
            server.start();

            System.out.printf("[INFO] Java Backend Orchestrator successfully started on port %d.\n", port);
            System.out.println("[INFO] Ready to receive network telemetry logs from frontend...");
            System.out.println("===============================================================");

            // Check initial ML microservice connection status
            boolean isMlOnline = mlClient.checkHealth();
            if (isMlOnline) {
                System.out.println("[STATUS] Python ML Microservice is ONLINE and connected.");
            } else {
                System.out.println("[WARN] Python ML Microservice is currently OFFLINE.");
                System.out.println("       Start Python service: uvicorn app:app --port 8000");
            }

        } catch (IOException e) {
            System.err.println("[FATAL] Could not start Java HTTP server: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}

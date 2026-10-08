package com.security.orchestrator;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.time.Instant;
import java.time.format.DateTimeFormatter;

/**
 * Thread-safe audit logger that records security threat evaluations to local disk.
 */
public class SecurityAuditLogger {
    private static final String AUDIT_LOG_FILE = "security_audit.log";

    public static synchronized void logEvent(String traceId, String clientIp, String threatCategory, String alertLevel, String verdict, long latencyMs) {
        String timestamp = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
        String logEntry = String.format(
            "[%s] [AUDIT] trace_id=%s ip=%s level=%s category=\"%s\" verdict=\"%s\" latency=%dms",
            timestamp, traceId, clientIp, alertLevel, threatCategory, verdict, latencyMs
        );

        // Print to standard out
        System.out.println(logEntry);

        // Append to local audit file
        try (FileWriter fw = new FileWriter(AUDIT_LOG_FILE, true);
             PrintWriter pw = new PrintWriter(fw)) {
            pw.println(logEntry);
        } catch (IOException e) {
            System.err.println("[ERROR] Failed to write to audit log file: " + e.getMessage());
        }
    }
}

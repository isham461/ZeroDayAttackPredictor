#!/usr/bin/env bash
# ZeroGuard - Full Stack Launcher

set -e
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

echo "================================================================"
echo "    Launching ZeroGuard Hybrid Zero-Day Detection Platform     "
echo "================================================================"

# 1. Start Python FastAPI Microservice (:8000)
echo "[1/3] Starting Python FastAPI ML Microservice on :8000..."
python3 -m uvicorn app:app --host 0.0.0.0 --port 8000 &
PYTHON_PID=$!

# 2. Compile and Start Java Security Orchestrator (:8080) if Java is present
echo "[2/3] Checking Java environment..."
if command -v javac >/dev/null 2>&1 && command -v java >/dev/null 2>&1; then
    echo "       Java runtime detected. Compiling and starting Orchestrator on :8080..."
    mkdir -p java_backend/bin
    javac -d java_backend/bin $(find java_backend/src/main/java -name "*.java")
    java -cp java_backend/bin com.security.orchestrator.OrchestratorServer &
    JAVA_PID=$!
else
    echo "       [INFO] Java runtime not installed on host PATH."
    echo "       The Frontend dashboard will communicate directly with the FastAPI engine (:8000)."
fi

# 3. Serve Frontend (:3000)
echo "[3/3] Serving Frontend Dashboard on http://localhost:3000..."
cd frontend
python3 -m http.server 3000 &
FRONTEND_PID=$!

echo ""
echo "================================================================"
echo "   ✅ Platform Ready!"
echo "   - Frontend UI        : http://localhost:3000"
echo "   - Python ML Engine   : http://localhost:8000/docs"
echo "   - Java Orchestrator  : http://localhost:8080/api/health (if Java enabled)"
echo "================================================================"
echo "Press Ctrl+C to terminate all services."

trap "kill $PYTHON_PID $FRONTEND_PID $JAVA_PID 2>/dev/null; exit 0" SIGINT SIGTERM
wait

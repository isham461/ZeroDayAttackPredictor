#!/usr/bin/env bash
# Runner script for Java Security Orchestrator

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$ROOT_DIR"

echo "======================================================="
echo "   Compiling & Starting Java Security Orchestrator    "
echo "======================================================="

BIN_DIR="$SCRIPT_DIR/bin"
mkdir -p "$BIN_DIR"

echo "[1/2] Compiling Java source files..."
javac -d "$BIN_DIR" $(find "$SCRIPT_DIR/src/main/java" -name "*.java")

echo "[2/2] Launching OrchestratorServer..."
java -cp "$BIN_DIR" com.security.orchestrator.OrchestratorServer

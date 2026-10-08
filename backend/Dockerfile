# Build stage
FROM maven:3.9.6-eclipse-temurin-17 AS build
WORKDIR /app
COPY pom.xml .
# Download dependencies (cache them)
RUN mvn dependency:go-offline -B
# Copy source code and build
COPY src ./src
RUN mvn clean package -DskipTests

# Run stage
FROM eclipse-temurin:17-jre-jammy
WORKDIR /app
# Install libpcap in case pcap4j needs it for live sniffing
RUN apt-get update && apt-get install -y libpcap-dev && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/backend-0.0.1-SNAPSHOT.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]

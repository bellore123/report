# ============================================================
# CyberShield Nexus — Multi-stage Dockerfile
# ENHANCEMENT (Part 1, #4): Containerized build + runtime
# ============================================================

# ---- Stage 1: Build ----
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /app
COPY pom.xml .
# Pre-fetch dependencies (cached layer, speeds up rebuilds)
RUN mvn -B dependency:go-offline
COPY src ./src
RUN mvn -B clean package -DskipTests

# ---- Stage 2: Runtime ----
FROM eclipse-temurin:21-jre-jammy
WORKDIR /app

# Non-root user for security best practice
RUN groupadd -r cybershield && useradd -r -g cybershield cybershield
COPY --from=build /app/target/*.jar app.jar
RUN mkdir -p /app/data && chown -R cybershield:cybershield /app

USER cybershield
EXPOSE 8081

# H2 file DB persists to /app/data — mount a volume there to keep data across restarts
ENTRYPOINT ["java", "-jar", "app.jar"]

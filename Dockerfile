# Build stage using Maven with JDK 11
FROM maven:3.8.4-openjdk-11 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests

# Final stage using OpenJDK 11 (rename this to "final")
FROM openjdk:11-jre-slim AS final
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar
COPY wait-for-it.sh /wait-for-it.sh
RUN chmod +x /wait-for-it.sh
EXPOSE 8080
CMD ["/wait-for-it.sh", "springboot-mysql-1:3306", "--", "java", "-jar", "app.jar"]


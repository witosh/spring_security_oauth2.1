FROM adoptopenjdk/openjdk8:alpine-slim

ADD target/default-auth-service-test-0.0.1-SNAPSHOT.jar /home/cscapprun/default-auth-service-test.jar

EXPOSE 8080

ENTRYPOINT ["java", "-agentlib:jdwp=transport=dt_socket,address=55551,server=y,suspend=n", "-Xmx256m", "-Djava.security.egd=file:/dev/./urandom", "-jar", "/home/cscapprun/default-auth-service-test.jar"]

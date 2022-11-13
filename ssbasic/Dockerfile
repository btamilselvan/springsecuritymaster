FROM openjdk:11-jre-slim

RUN apt-get update -y

#RUN apt-get install fontconfig -y

RUN apt-get install wget -y

# The application's jar file.
ARG JAR_FILE

#ENV profile dev

# Add the application's jar to the container
ADD ${JAR_FILE} ssbasic.jar

# Run the jar file 
ENTRYPOINT ["java", "-jar", "ssbasic.jar"]
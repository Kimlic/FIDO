FROM tomcat:9-jre8-alpine
RUN ["rm", "-fr", "/usr/local/tomcat/webapps/ROOT"]
COPY fidouaf/target/fidouaf-0.0.1-SNAPSHOT.war /usr/local/tomcat/webapps/ROOT.war
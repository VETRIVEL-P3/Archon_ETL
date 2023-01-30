FROM docker-registry2.platform3solutions.com/archon/alpine-java:11

VOLUME /tmp

ARG PORT=8100

ARG ARCHON_AUTHENTICATION_SERVICE_JAR=./target/archon-authentication-service-0.0.1-SNAPSHOT.jar

COPY ${ARCHON_AUTHENTICATION_SERVICE_JAR} start-archon-authentication-service.sh /tmp/

ENV APP_HOME /tmp/
ENV PORT ${PORT}

EXPOSE ${PORT}

RUN apk update \
    && apk add --update ttf-ubuntu-font-family --no-cache bash  \
    && chmod a+x /tmp/*.sh \
    && mv /tmp/start-archon-authentication-service.sh /usr/bin \
    && rm /tmp/*

CMD dot -Tpng  


ENTRYPOINT [ "start-archon-authentication-service.sh" ]

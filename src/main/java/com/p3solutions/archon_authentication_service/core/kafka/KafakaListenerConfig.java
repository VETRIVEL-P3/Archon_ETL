package com.p3solutions.archon_authentication_service.core.kafka;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.p3solutions.archon_authentication_service.core.configuration.logback.LogBackConfiguration;
import com.p3solutions.common_beans_dto.administration.beans.RetentionConfig;
import com.p3solutions.common_beans_dto.common_beans.KafkaMessenger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;


@Component
public class KafakaListenerConfig {
    private final Logger logger = LoggerFactory.getLogger(KafakaListenerConfig.class);

    @Autowired
    private LogBackConfiguration logBackConfiguration;

    @KafkaListener(topics = "${kafka.topic.name.logback-rolling}")
    public void updateHistoryForLogback(KafkaMessenger messenger) throws Exception {
        logger.info("Received greeting message from logback: {}", messenger);
        RetentionConfig retentionConfig = new ObjectMapper().readValue(messenger.getJobInput(), RetentionConfig.class);
        logBackConfiguration.updateLogBackConfig(retentionConfig);
        logger.info("Authentication Service");
    }

}

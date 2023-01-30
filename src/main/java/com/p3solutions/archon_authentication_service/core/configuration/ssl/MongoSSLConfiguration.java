package com.p3solutions.archon_authentication_service.core.configuration.ssl;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class MongoSSLConfiguration {

    @Value(value = "${server.ssl.trust-store}")
    private String trustStore;
    @Value(value = "${server.ssl.trust-store-password}")
    private String trustStorePassword;
    @Value(value = "${mongo.security.enableSSL}")
    private Boolean enableMongoDbSSL;
    @Value(value = "${server.ssl.enabled}")
    private Boolean enabledSSL;

   /* @Bean
    public MongoClientOptions mongoClientOptions() {
        if (enabledSSL || enableMongoDbSSL) {
            System.setProperty("javax.net.ssl.trustStore", trustStore);
            System.setProperty("javax.net.ssl.trustStorePassword", trustStorePassword);
        }
        MongoClientOptions.Builder builder = MongoClientOptions.builder();
        return builder.sslEnabled(enableMongoDbSSL).build();
    }*/

}

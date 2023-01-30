package com.p3solutions.archon_authentication_service.core.authentication.security.saml.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.*;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/**
 * This configuration bean is used to define the role mapping of saml roles to Archon groups
 * @author seelan
 */
@Configuration
public class RoleMapping {

    @Value("${saml.role.mapping-file}")
    private String roleMapFile;

    @Bean("roleMapper")
    public Map<String, String> roleMapper() {
        Map<String, String> roleMap = new HashMap<>();
        try {
            Properties roleProperties = new Properties();
            InputStream is = new FileInputStream(roleMapFile);
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
                String line;
                while (!(line = reader.readLine()).isEmpty()) {
                    String[] split = line.split("=");
                    roleProperties.setProperty(split[0], split[1]);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            Set<Object> allKeys = roleProperties.keySet();
            if (allKeys.isEmpty())
                return roleMap;
            for (Object roleName: allKeys) {
                roleMap.put(roleName.toString(), roleProperties.getProperty(roleName.toString()));
            }
        } catch (Exception ex) {

        }
        return roleMap;
    }
}

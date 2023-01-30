package com.p3solutions.archon_authentication_service.core.authentication;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWEDecryptionKeySelector;
import com.nimbusds.jose.proc.JWEKeySelector;
import com.nimbusds.jose.proc.SimpleSecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

@Component
@Slf4j
public class JwtUtility
{
   // private static final Logger LOGGER = Loggers.getLogger("JwtUtility");
    @Autowired
    Environment environment;
   private JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256);
    public Map<String,String> getDecodedToken(String token)  {
        Map<String,String> claimMap=new HashMap();
        byte[] secretKey = environment.getProperty("jwt.token.sso.secret-key").getBytes();
        try {
        ConfigurableJWTProcessor<SimpleSecurityContext> jwtProcessor = new DefaultJWTProcessor<SimpleSecurityContext>();
        JWKSource<SimpleSecurityContext> jweKeySource = new ImmutableSecret<SimpleSecurityContext>(secretKey);
        JWEKeySelector<SimpleSecurityContext> jweKeySelector =
                new JWEDecryptionKeySelector<SimpleSecurityContext>(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256, jweKeySource);
        jwtProcessor.setJWEKeySelector(jweKeySelector);
        JWTClaimsSet jwtClaimsSet = null;
            jwtClaimsSet = jwtProcessor.process(token, null);
        claimMap.put("userName",(String) jwtClaimsSet.getClaim("userName"));
        claimMap.put("roles",(String) jwtClaimsSet.getClaim("roles"));

        } catch (ParseException e) {
            log.error("Exception Occur's:", e);
        } catch (BadJOSEException e) {
            log.error("Exception Occur's:", e);
        } catch (JOSEException e) {
            log.error("Exception Occur's:", e);
        }
        return claimMap;
    }
}

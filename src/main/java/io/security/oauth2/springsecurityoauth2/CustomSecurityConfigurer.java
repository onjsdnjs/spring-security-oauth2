package io.security.oauth2.springsecurityoauth2;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

public class CustomSecurityConfigurer
        extends AbstractHttpConfigurer<CustomSecurityConfigurer, HttpSecurity> {
    private boolean isSecure;

    @Override
    public void init(HttpSecurity builder) throws Exception {
        super.init(builder);
    }
    @Override
    public void configure(HttpSecurity builder) throws Exception {
        super.configure(builder);
    }
    public CustomSecurityConfigurer setFlag(boolean isSecure){
        this.isSecure = isSecure;
        return this;
    }
}

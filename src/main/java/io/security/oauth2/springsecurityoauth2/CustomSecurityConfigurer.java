package io.security.oauth2.springsecurityoauth2;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

public class CustomSecurityConfigurer
        extends AbstractHttpConfigurer<CustomSecurityConfigurer, HttpSecurity> {
    private boolean isSecure;

    @Override
    public void init(HttpSecurity builder) throws Exception {
        super.init(builder);
        System.out.println("init method starting..");
    }
    @Override
    public void configure(HttpSecurity builder) throws Exception {
        super.configure(builder);
        if(isSecure){
            System.out.println("https is required");
        }else{
            System.out.println("https is optional");
        }
        System.out.println("configure method starting..");
    }
    public CustomSecurityConfigurer setFlag(boolean isSecure){
        this.isSecure = isSecure;
        return this;
    }
}

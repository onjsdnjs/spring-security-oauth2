package io.security.oauth2.springsecurityoauth2.common.converter;

import io.security.oauth2.springsecurityoauth2.model.users.ProviderUser;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

@Component
public final class DelegatingProviderUserConverter implements ProviderUserConverter<ProviderUserRequest,ProviderUser> {
    private final List<ProviderUserConverter<ProviderUserRequest, ProviderUser>> converters;

    public DelegatingProviderUserConverter() {

        List<ProviderUserConverter<ProviderUserRequest,ProviderUser>> providerUserConverters = Arrays.asList(
                new UserDetailsProviderUserConverter(),
                new OAuth2GoogleProviderUserConverter(),
                new OAuth2NaverProviderUserConverter(),
                new OAuth2KakaoProviderUserConverter(),
                new OAuth2KakaoOidcProviderUserConverter());

        this.converters = Collections.unmodifiableList(new LinkedList<>(providerUserConverters));
    }

    @Nullable
    @Override
    public ProviderUser convert(ProviderUserRequest providerUserRequest) {
        Assert.notNull(providerUserRequest, "providerUserRequest cannot be null");

        for (ProviderUserConverter<ProviderUserRequest,ProviderUser> converter : this.converters) {
            ProviderUser providerUser = converter.convert(providerUserRequest);
            if (providerUser != null) {
                return providerUser;
            }
        }
        return null;
    }
}

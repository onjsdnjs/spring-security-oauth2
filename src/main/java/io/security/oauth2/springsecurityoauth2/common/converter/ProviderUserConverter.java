package io.security.oauth2.springsecurityoauth2.common.converter;

public interface ProviderUserConverter<T,R> {
    R convert(T t);
}

package io.security.oauth2.springsecurityoauth2.model.attributes;

import lombok.Builder;
import lombok.Data;

import java.util.Map;

@Data
@Builder
public class Attributes {

    private Map<String, Object> attributes;
    private Map<String, Object> subAttributes;

}

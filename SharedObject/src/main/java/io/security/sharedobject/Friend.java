package io.security.sharedobject;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class Friend {
    private String name;
    private int age;
    private String gender;
}

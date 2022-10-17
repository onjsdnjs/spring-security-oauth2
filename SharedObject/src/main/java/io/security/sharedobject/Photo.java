package io.security.sharedobject;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Photo implements Serializable {
    private String userId;
    private String photoId;
    private String photoTitle;
    private String photoDescription;
}

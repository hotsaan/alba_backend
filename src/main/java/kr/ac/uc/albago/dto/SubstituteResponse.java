package kr.ac.uc.albago.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class SubstituteResponse {
    private Long id;
    private Long jobPostId;
    private String title;
    private String status;
}

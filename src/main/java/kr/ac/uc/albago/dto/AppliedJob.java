package kr.ac.uc.albago.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AppliedJob {

    private Long id;        // applicationId
    private Long jobPostId; // 공고 ID
}

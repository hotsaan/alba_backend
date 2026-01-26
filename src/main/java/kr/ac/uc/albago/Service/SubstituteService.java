package kr.ac.uc.albago.Service;

import kr.ac.uc.albago.dto.SubstituteResponse;
import kr.ac.uc.albago.entity.SubstituteEntity;
import kr.ac.uc.albago.repository.SubstituteRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class SubstituteService {

    private final SubstituteRepository substituteRepository;

    public List<SubstituteResponse> getMySubstitutes(String email) {
        return substituteRepository.findByUser_Email(email).stream()
                .map(s -> new SubstituteResponse(
                        s.getId(),
                        s.getJobPost().getId(),
                        s.getJobPost().getTitle(),
                        s.getStatus()
                ))
                .toList();
    }
}

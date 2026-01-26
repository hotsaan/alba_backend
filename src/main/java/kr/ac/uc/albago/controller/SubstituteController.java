package kr.ac.uc.albago.controller;

import kr.ac.uc.albago.Service.SubstituteService;
import kr.ac.uc.albago.dto.SubstituteResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/substitute")
@RequiredArgsConstructor
public class SubstituteController {

    private final SubstituteService substituteService;

    @GetMapping("/my")
    public List<SubstituteResponse> mySubstitutes(Authentication authentication) {
        String email = authentication.getName();
        return substituteService.getMySubstitutes(email);
    }
}

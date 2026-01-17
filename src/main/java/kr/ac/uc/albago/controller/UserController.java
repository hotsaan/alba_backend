package kr.ac.uc.albago.controller;

import kr.ac.uc.albago.Service.FileStorageService;
import kr.ac.uc.albago.entity.UserEntity;
import kr.ac.uc.albago.repository.UserRepository;
import kr.ac.uc.albago.dto.UserInfoResponse;
import kr.ac.uc.albago.dto.UserInfoUpdateRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api") // 이 컨트롤러의 모든 API는 /api로 시작
@CrossOrigin(origins = "*") // 개발 단계에서는 전체 허용 (운영 시 제한 권장)
public class UserController {

    @Autowired
    private UserRepository userRepo;

    @Autowired
    private FileStorageService fileStorageService;

    /**
     * 로그인된 사용자 정보 조회 API
     * - JWT 인증 후 호출됨
     * - SecurityContext에 저장된 사용자 이메일 기준으로 조회
     */
    @GetMapping("/userinfo")
    public ResponseEntity<?> getUserInfo() {

        // 현재 인증된 사용자 정보 가져오기
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            // 보통 SecurityConfig에서 이미 걸러지지만, 방어 코드
            return ResponseEntity.status(401).body("인증되지 않은 사용자입니다.");
        }

        // JWT subject (email)
        String userEmail = authentication.getName();

        Optional<UserEntity> userOpt = userRepo.findByEmail(userEmail);
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(404).body("사용자를 찾을 수 없습니다.");
        }

        UserEntity user = userOpt.get();

        // 프론트로 전달할 사용자 정보 DTO 구성
        UserInfoResponse userInfo = new UserInfoResponse();
        userInfo.setUsername(user.getUsername());
        userInfo.setEmail(user.getEmail());
        userInfo.setRole(user.getRole());
        userInfo.setAboutMe(user.getAboutMe());
        userInfo.setAge(user.getAge());
        userInfo.setGender(user.getGender());
        userInfo.setBirthDate(user.getBirthDate());
        userInfo.setAddress(user.getAddress());
        userInfo.setProfileImageUrl(user.getProfileImageUrl());

        // TODO:
        // sharedCount / postsCount / starCount
        // → 다른 테이블 연계 후 서비스 계층에서 계산 예정

        return ResponseEntity.ok(userInfo);
    }

    /**
     * 로그인된 사용자 정보 수정 API
     * - 전달된 필드만 선택적으로 업데이트
     */
    @PutMapping("/userinfo")
    public ResponseEntity<?> updateUserInfo(@RequestBody UserInfoUpdateRequest request) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String userEmail = authentication.getName();

        Optional<UserEntity> userOpt = userRepo.findByEmail(userEmail);
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(404).body("사용자를 찾을 수 없습니다.");
        }

        UserEntity user = userOpt.get();

        if (request.getUsername() != null) {
            user.setUsername(request.getUsername());
        }
        if (request.getGender() != null) {
            user.setGender(request.getGender());
        }
        if (request.getBirthDate() != null) {
            user.setBirthDate(
                    LocalDate.parse(
                            request.getBirthDate(),
                            DateTimeFormatter.ofPattern("yyyy/MM/dd")
                    )
            );
        }
        if (request.getAddress() != null) {
            user.setAddress(request.getAddress());
        }
        if (request.getAboutMe() != null) {
            user.setAboutMe(request.getAboutMe());
        }
        if (request.getProfileImageUrl() != null) {
            user.setProfileImageUrl(request.getProfileImageUrl());
        }

        userRepo.save(user);

        return ResponseEntity.ok().build();
    }

    /**
     * 프로필 이미지 업로드 API
     * - 이미지 파일 저장 후 접근 가능한 URL 반환
     */
    @PostMapping("/user/profile-image")
    public ResponseEntity<?> uploadProfileImage(
            @RequestParam("image") MultipartFile file
    ) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String userEmail = authentication.getName();

        Optional<UserEntity> userOpt = userRepo.findByEmail(userEmail);
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(404).body("사용자를 찾을 수 없습니다.");
        }

        // 파일 저장
        String fileName = fileStorageService.storeFile(file);

        // 접근 가능한 URL 생성
        String fileDownloadUri = ServletUriComponentsBuilder
                .fromCurrentContextPath()
                .path("/uploads/")
                .path(fileName)
                .toUriString();

        // 사용자 프로필 이미지 URL 업데이트
        UserEntity user = userOpt.get();
        user.setProfileImageUrl(fileDownloadUri);
        userRepo.save(user);

        return ResponseEntity.ok(Map.of("url", fileDownloadUri));
    }
}

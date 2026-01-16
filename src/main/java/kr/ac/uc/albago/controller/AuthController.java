package kr.ac.uc.albago.controller;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import jakarta.transaction.Transactional;
import kr.ac.uc.albago.Service.AuthService;
import kr.ac.uc.albago.Security.JwtUtil;
import kr.ac.uc.albago.dto.LoginResponse;
import kr.ac.uc.albago.entity.RefreshToken;
import kr.ac.uc.albago.entity.UserEntity;
import kr.ac.uc.albago.repository.RefreshTokenRepository;
import kr.ac.uc.albago.repository.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken.Payload;


import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.*;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class AuthController {

    // ===== 의존성 주입 =====
    @Autowired
    private AuthService authService;          // 로그인 핵심 비즈니스 로직

    @Autowired
    private JwtUtil jwtUtil;                  // JWT 생성/검증 유틸

    @Autowired
    private RefreshTokenRepository rtRepo;    // RefreshToken 저장소

    @Autowired
    private UserRepository userRepo;          // 사용자 저장소

    @Autowired
    private PasswordEncoder passwordEncoder;  // 비밀번호 암호화

    // Google OAuth Client ID
    @Value("${google.clientId}")
    private String googleClientId;

    // 이메일 형식 검증용 정규식
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$"
    );

    // =====================================================
    // 1 일반 로그인 (이메일 + 비밀번호)
    // =====================================================
    @PostMapping("/login")
    @Transactional
    public ResponseEntity<?> login(@RequestBody Map<String, String> loginData) {

        String email = loginData.get("email");
        String password = loginData.get("password");

        // 필수값 검증
        if (email == null || password == null) {
            return ResponseEntity.badRequest().body("Email and password are required.");
        }

        // 로그인 시도
        LoginResponse response = authService.login(email, password);

        // 로그인 실패
        if (response == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid credentials");
        }

        // 로그인 성공
        return ResponseEntity.ok(response);
    }

    // =====================================================
    // 2 회원가입
    //  - isPartial=true : 아이디/이메일 중복 체크용
    //  - isPartial=false : 실제 회원가입
    // =====================================================
    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(
            @RequestBody UserEntity user,
            @RequestParam(name = "isPartial", required = false) Boolean isPartial
    ) {

        Map<String, String> errors = new HashMap<>();

        // ---------- 아이디 검증 ----------
        if (user.getUserId() == null || user.getUserId().isBlank()) {
            errors.put("userId", "ID is required.");
        } else if (!user.getUserId().matches("^[a-zA-Z][a-zA-Z0-9]{3,19}$")) {
            errors.put("userId", "Must start with a letter and be 4–20 chars.");
        } else if (userRepo.existsByUserId(user.getUserId())) {
            errors.put("userId", "That ID is already in use.");
        }

        // ---------- 전체 회원가입일 때만 검증 ----------
        if (isPartial == null || !isPartial) {

            // 이메일 검증
            if (user.getEmail() == null || user.getEmail().isBlank()) {
                errors.put("email", "Email is required.");
            } else if (!EMAIL_PATTERN.matcher(user.getEmail()).matches()) {
                errors.put("email", "Invalid email format.");
            } else if (userRepo.existsByEmail(user.getEmail())) {
                errors.put("email", "That email is already registered.");
            }

            // 비밀번호 검증
            if (user.getPassword() == null || user.getPassword().isBlank()) {
                errors.put("password", "Password is required.");
            }

            // 닉네임 검증
            if (user.getUsername() == null || user.getUsername().isBlank()) {
                errors.put("username", "Username is required.");
            }
        }

        // ---------- 에러 반환 ----------
        if (!errors.isEmpty()) {
            return ResponseEntity.ok(Map.of(
                    "success", false,
                    "errors", errors
            ));
        }

        // ---------- 중복 체크만 하는 경우 ----------
        if (isPartial != null && isPartial) {
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "ID and Email are available."
            ));
        }

        // ---------- 실제 회원가입 처리 ----------
        user.setPassword(passwordEncoder.encode(user.getPassword())); // 비밀번호 암호화
        user.setLastLogin(null);

        // 기본값 세팅
        if (user.getAge() == null) user.setAge(0);
        if (user.getPhoneNumber() == null) user.setPhoneNumber("");
        if (user.getAddress() == null) user.setAddress("");
        if (user.getBusinessInfo() == null) user.setBusinessInfo("");

        // 역할 기본값
        if (user.getRole() == null ||
                (!user.getRole().equals("user") && !user.getRole().equals("employer"))) {
            user.setRole("user");
        }

        if (user.getIsActive() == null) user.setIsActive(true);
        if (user.getSnsProvider() == null) user.setSnsProvider("none");

        // DB 저장
        UserEntity saved = userRepo.save(user);

        return ResponseEntity.ok(Map.of(
                "success", true,
                "user", saved
        ));
    }

    // =====================================================
    // 3 AccessToken 재발급 (RefreshToken 사용)
    // =====================================================
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody Map<String, String> body) {

        String refreshToken = body.get("refreshToken");

        if (refreshToken == null || refreshToken.isBlank()) {
            return ResponseEntity.badRequest()
                    .body("Refresh token is required.");
        }
        // 🔴 RefreshToken이 JWT 자체로 유효한지 검증이 없음
        //  위조된 토큰도 DB에 있으면 통과 가능해서 추가

      if (!jwtUtil.validateToken(refreshToken)) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body("Invalid refresh token.");
    }


        // RefreshToken 유효성 + 만료 체크
        Optional<RefreshToken> optionalToken = rtRepo.findByToken(refreshToken)
                .filter(rt -> rt.getExpiryDate().isAfter(LocalDateTime.now()));

        if (optionalToken.isPresent()) {

            String email = optionalToken.get().getUsername();
            Optional<UserEntity> userOpt = userRepo.findByEmail(email);

            String role = userOpt.map(UserEntity::getRole).orElse("user");

            // 회사 ID (사업자 계정일 경우)
            String companyId = userOpt
                    .filter(u -> u.getCompanies() != null && !u.getCompanies().isEmpty())
                    .map(u -> u.getCompanies().get(0).getCompanyId())
                    .orElse(null);

            // 새 AccessToken 발급
            String newAccessToken =
                    jwtUtil.generateToken(email, role, companyId, 15);

            return ResponseEntity.ok(Map.of(
                    "accessToken", newAccessToken,
                    "role", role
            ));
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body("Invalid or expired refresh token.");
    }

    // =====================================================
    // 4 구글 소셜 로그인
    // =====================================================
    @PostMapping("/google-login")
    public ResponseEntity<?> googleLogin(@RequestBody Map<String, String> body) {

        String idTokenString = body.get("idToken");

        if (idTokenString == null || idTokenString.isBlank()) {
            return ResponseEntity.badRequest().body("idToken is required.");
        }

        try {
            // Google ID Token 검증기 생성
            GoogleIdTokenVerifier verifier =
                    new GoogleIdTokenVerifier.Builder(
                            new NetHttpTransport(),
                            JacksonFactory.getDefaultInstance()
                    )
                            .setAudience(Collections.singletonList(googleClientId))
                            .build();

            GoogleIdToken idToken = verifier.verify(idTokenString);

            if (idToken == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body("Invalid ID token.");
            }

            // Google 사용자 정보
            Payload payload = idToken.getPayload();
            String email = payload.getEmail();

            Optional<UserEntity> userOpt = userRepo.findByEmail(email);
            UserEntity user;

            if (userOpt.isPresent()) {
                // 기존 사용자
                user = userOpt.get();

                // 로컬 계정과 충돌 방지
                if (!"google".equals(user.getSnsProvider())) {
                    return ResponseEntity.status(HttpStatus.CONFLICT)
                            .body("이미 로컬 계정이 존재합니다.");
                }
            } else {
                //  최초 구글 로그인 → 자동 회원가입
                user = new UserEntity();
                user.setEmail(email);
                user.setUsername(payload.get("name").toString());
                user.setUserId(UUID.randomUUID()
                        .toString()
                        .replace("-", "")
                        .substring(0, 16));
                user.setPassword(null);  // 🔴 소셜 로그인 계정은 password가 없어야 함
                user.setRole("user");
                user.setSnsProvider("google");
                user.setIsActive(true);

                // 🔴 createdAt / updatedAt 직접 세팅하면 안 됨
                // 👉 Entity @PrePersist / DB default에 맡기는 게 정답
                // user.setCreatedAt(...)
                // user.setUpdatedAt(...)


                user = userRepo.save(user);
            }

            // 회사 ID
            String companyId =
                    (user.getCompanies() != null && !user.getCompanies().isEmpty())
                            ? user.getCompanies().get(0).getCompanyId()
                            : null;

            // 토큰 발급
            String accessToken =
                    jwtUtil.generateToken(user.getEmail(), user.getRole(), companyId, 15);
            String refreshToken =
                    jwtUtil.generateToken(user.getEmail(), user.getRole(), companyId, 60 * 24 * 7);

            // 🔴 기존 RefreshToken 삭제 안 하면 토큰 누적됨

        rtRepo.deleteByUsername(user.getEmail());



            // RefreshToken 저장
            RefreshToken rt = new RefreshToken();
            rt.setToken(refreshToken);
            rt.setUsername(user.getEmail());
            rt.setExpiryDate(LocalDateTime.now().plusDays(7));
            rtRepo.save(rt);

            return ResponseEntity.ok(
                    new LoginResponse(
                            accessToken,
                            refreshToken,
                            user.getRole(),
                            user.getEmail(),
                            companyId != null ? companyId : ""
                    )
            );

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Google login failed");
        }
    }
}

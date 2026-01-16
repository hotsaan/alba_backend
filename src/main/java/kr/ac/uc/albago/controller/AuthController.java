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

    @Autowired
    private AuthService authService;
    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private RefreshTokenRepository rtRepo;
    @Autowired
    private UserRepository userRepo;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Value("${google.clientId}")
    private String googleClientId;

    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$"
    );

    @PostMapping("/login")
    @Transactional
    public ResponseEntity<?> login(@RequestBody Map<String, String> loginData) {
        String email = loginData.get("email");
        String password = loginData.get("password");

        if (email == null || password == null) {
            return ResponseEntity.badRequest().body("Email and password are required.");
        }

        LoginResponse response = authService.login(email, password);
        if (response == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }

        return ResponseEntity.ok(response);
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(
            @RequestBody UserEntity user,
            @RequestParam(name = "isPartial", required = false) Boolean isPartial
    ) {
        Map<String, String> errors = new HashMap<>();

        if (user.getUserId() == null || user.getUserId().isBlank()) {
            errors.put("userId", "ID is required.");
        } else if (!user.getUserId().matches("^[a-zA-Z][a-zA-Z0-9]{3,19}$")) {
            errors.put("userId", "Must start with a letter and be 4–20 chars.");
        } else if (userRepo.existsByUserId(user.getUserId())) {
            errors.put("userId", "That ID is already in use.");
        }

        // --- START OF THE FIX ---
        // The email, password, and username validations should ONLY run for a full registration.
        // The original code incorrectly had the email validation outside this block.
        if (isPartial == null || !isPartial) {
            // (This email block was moved here)
            if (user.getEmail() == null || user.getEmail().isBlank()) {
                errors.put("email", "Email is required.");
            } else if (!EMAIL_PATTERN.matcher(user.getEmail()).matches()) {
                errors.put("email", "Invalid email format.");
            } else if (userRepo.existsByEmail(user.getEmail())) {
                errors.put("email", "That email is already registered.");
            }

            // (This password validation was already correctly here)
            if (user.getPassword() == null || user.getPassword().isBlank()) {
                errors.put("password", "Password is required.");
            }
            // (This username validation was already correctly here)
            if (user.getUsername() == null || user.getUsername().isBlank()) {
                errors.put("username", "Username is required.");
            }
        }
        // --- END OF THE FIX ---

        if (!errors.isEmpty()) {
            return ResponseEntity.ok(Map.of("success", false, "errors", errors));
        }

        if (isPartial != null && isPartial) {
            return ResponseEntity.ok(Map.of("success", true, "message", "ID and Email are available."));
        }

        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setLastLogin(null);
        if (user.getAge() == null) user.setAge(0);
        if (user.getPhoneNumber() == null) user.setPhoneNumber("");
        if (user.getAddress() == null) user.setAddress("");
        if (user.getBusinessInfo() == null) user.setBusinessInfo("");
        if (user.getRole() == null || (!user.getRole().equals("user") && !user.getRole().equals("employer"))) {
            user.setRole("user");
        }
        if (user.getIsActive() == null) user.setIsActive(true);
        if (user.getSnsProvider() == null) user.setSnsProvider("none");

        UserEntity saved = userRepo.save(user);

        return ResponseEntity.ok(Map.of(
                "success", true,
                "user", saved
        ));
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody Map<String, String> body) {
        String refreshToken = body.get("refreshToken");
        if (refreshToken == null || refreshToken.isBlank()) {
            return ResponseEntity.badRequest().body("Refresh token is required.");
        }

        Optional<RefreshToken> optionalToken = rtRepo.findByToken(refreshToken)
                .filter(rt -> rt.getExpiryDate().isAfter(LocalDateTime.now()));

        if (optionalToken.isPresent()) {
            String username = optionalToken.get().getUsername();
            Optional<UserEntity> userOpt = userRepo.findByEmail(username);
            String role = userOpt.map(UserEntity::getRole).orElse("user");

            String companyId = userOpt.filter(u -> (u.getCompanies() != null && !u.getCompanies().isEmpty()))
                    .map(u -> u.getCompanies().get(0).getCompanyId())
                    .orElse(null);

            String newAccessToken = jwtUtil.generateToken(username, role, companyId, 15);
            return ResponseEntity.ok(Map.of("accessToken", newAccessToken, "role", role));
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid or expired refresh token.");
        }
    }

    @PostMapping("/google-login")
    public ResponseEntity<?> googleLogin(@RequestBody Map<String, String> body) {
        String idTokenString = body.get("idToken");
        if (idTokenString == null || idTokenString.isBlank()) {
            return ResponseEntity.badRequest().body("idToken is required.");
        }

        try {
            GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(
                    new NetHttpTransport(), JacksonFactory.getDefaultInstance())
                    .setAudience(Collections.singletonList(googleClientId))
                    .build();

            GoogleIdToken idToken = verifier.verify(idTokenString);

            if (idToken == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid ID token.");
            }

            Payload payload = idToken.getPayload();
            String email = payload.getEmail();

            Optional<UserEntity> userOpt = userRepo.findByEmail(email);
            UserEntity user;

            if (userOpt.isPresent()) {
                user = userOpt.get();

                if (!"google".equals(user.getSnsProvider())) {
                    return ResponseEntity.status(HttpStatus.CONFLICT).body("이미 로컬 계정이 존재합니다.");
                }

            } else {
                // 🔥 구글 유저 자동 회원가입 처리
                user = new UserEntity();
                user.setEmail(email);
                user.setUsername(payload.get("name").toString());
                user.setUserId(UUID.randomUUID().toString().replace("-", "").substring(0, 16)); // 랜덤 ID
                user.setPassword(""); // 소셜 로그인은 패스워드 없음
                user.setRole("user"); // 기본 권한
                user.setSnsProvider("google");
                user.setIsActive(true);
                user.setCreatedAt(Timestamp.valueOf(LocalDateTime.now()));
                user.setUpdatedAt(Timestamp.valueOf(LocalDateTime.now()));
                user = userRepo.save(user); // 🧨 여기서 회원가입 완료
            }

            String companyId = (user.getCompanies() != null && !user.getCompanies().isEmpty())
                    ? user.getCompanies().get(0).getCompanyId() : null;

            String accessToken = jwtUtil.generateToken(user.getEmail(), user.getRole(), companyId, 15);
            String refreshToken = jwtUtil.generateToken(user.getEmail(), user.getRole(), companyId, 15);

            RefreshToken rt = new RefreshToken();
            rt.setToken(refreshToken);
            rt.setUsername(user.getEmail());
            rt.setExpiryDate(LocalDateTime.now().plusDays(7));
            rtRepo.save(rt);

            return ResponseEntity.ok(new LoginResponse(
                    accessToken,
                    refreshToken,
                    user.getRole(),
                    user.getEmail(),
                    companyId != null ? companyId : ""
            ));

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Google login failed");
        }
    }
}
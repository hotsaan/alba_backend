package kr.ac.uc.albago.Security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.http.HttpMethod;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private JwtFilter jwtFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        // 1. 인증 없이 접근 가능한 API
                        .requestMatchers(
                                "/api/login",
                                "/api/register",
                                "/api/refresh",
                                "/api/google-login",
                                "/api/check-company-id-duplicate",
                                "/uploads/**",
                                "/api/map/**"
                        ).permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/jobposts").permitAll()  // 공고 조회는 누구나 가능

                        // 2. USER 권한이 필요한 요청
                        .requestMatchers(HttpMethod.GET, "/api/userinfo").hasRole("USER")  // 사용자 정보 조회는 ROLE_USER만
                        .requestMatchers(HttpMethod.PUT, "/api/userinfo").hasRole("USER")  // 사용자 정보 수정도 ROLE_USER만
                        .requestMatchers(HttpMethod.POST, "/api/user/profile-image").hasRole("USER")  // 프로필 이미지 수정도 ROLE_USER만
                        .requestMatchers(HttpMethod.POST, "/api/applications/**").hasRole("USER")  // 지원 신청은 ROLE_USER만

                        // 3. `POST`와 `GET` 요청에 대해 `/api/jobseeker/job-applications` 권한 설정
                        .requestMatchers(HttpMethod.GET, "/api/jobseeker/job-applications").hasRole("USER")  // `GET` 요청은 ROLE_USER만
                        .requestMatchers(HttpMethod.POST, "/api/jobseeker/job-applications").hasRole("USER") // `POST` 요청은 ROLE_USER만

                        // 4. EMPLOYER 전용 요청 (구체적 → 일반 순서로)
                        .requestMatchers(HttpMethod.POST, "/api/employer/jobposts").hasRole("EMPLOYER")  // 공고 등록은 ROLE_EMPLOYER만
                        .requestMatchers(HttpMethod.PUT, "/api/jobposts/**").hasRole("EMPLOYER")  // 공고 수정은 ROLE_EMPLOYER만
                        .requestMatchers(HttpMethod.DELETE, "/api/jobposts/**").hasRole("EMPLOYER")  // 공고 삭제는 ROLE_EMPLOYER만
                        .requestMatchers("/api/employer/**").hasRole("EMPLOYER")  // EMPLOYER 관련 API는 ROLE_EMPLOYER만

                        // 5. 공통 인증 필요 API (jobpost 상세 등)
                        .requestMatchers(HttpMethod.GET, "/api/jobposts/**").authenticated()  // 공고 상세는 누구나 볼 수 있지만 로그인 필요

                        // 6. 기타 모든 요청은 인증 필요
                        .anyRequest().authenticated()  // 나머지 요청은 모두 인증 필요
                )
                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

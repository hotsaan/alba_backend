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
                .sessionManagement(sess ->
                        sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authorizeHttpRequests(auth -> auth

                        // =====================
                        // 1. 인증 없이 접근
                        // =====================
                        .requestMatchers(
                                "/api/login",
                                "/api/register",
                                "/api/refresh",
                                "/api/google-login",
                                "/api/check-company-id-duplicate",
                                "/uploads/**",
                                "/api/map/**"
                        ).permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/jobposts").permitAll()

                        // =====================
                        // 2. USER
                        // =====================
                        .requestMatchers(HttpMethod.GET, "/api/userinfo").hasAuthority("user")
                        .requestMatchers(HttpMethod.PUT, "/api/userinfo").hasAuthority("user")
                        .requestMatchers(HttpMethod.POST, "/api/user/profile-image").hasAuthority("user")

                        .requestMatchers(HttpMethod.POST, "/api/applications/**").hasAuthority("user")
                        .requestMatchers(HttpMethod.GET, "/api/applications").hasAuthority("user")
                        .requestMatchers(HttpMethod.DELETE, "/api/applications/**").hasAuthority("user")
                        .requestMatchers(HttpMethod.GET, "/api/substitute/my").hasAuthority("user")

                        // =====================
                        // 3. EMPLOYER
                        // =====================
                        .requestMatchers(HttpMethod.POST, "/api/employer/jobposts").hasAuthority("employer")
                        .requestMatchers(HttpMethod.GET, "/api/employer/jobposts/**").hasAuthority("employer")
                        .requestMatchers(HttpMethod.PUT, "/api/jobposts/**").hasAuthority("employer")
                        .requestMatchers(HttpMethod.DELETE, "/api/jobposts/**").hasAuthority("employer")

                        // 지원자 조회
                        .requestMatchers(HttpMethod.GET, "/api/employer/applicants/**").hasAuthority("employer")

                        // 지원자 수락
                        .requestMatchers(HttpMethod.POST, "/api/employer/applications/*/accept").hasAuthority("employer")

                        // =====================
                        // 4. 나머지
                        // =====================
                        .anyRequest().authenticated()
                )

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

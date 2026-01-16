package kr.ac.uc.albago.Security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String header = request.getHeader("Authorization");

        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7); // Bearer 잘라내기

            if (jwtUtil.validateToken(token)) {
                String username = jwtUtil.extractUsername(token);
                String role = jwtUtil.extractRole(token); // ex: "EMPLOYER" or "ROLE_EMPLOYER"

                // ROLE_ 접두사 없으면 붙이기
                if (!role.startsWith("ROLE_")) {
                    role = "ROLE_" + role;
                }

                List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(role));

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(username, null, authorities);

                SecurityContextHolder.getContext().setAuthentication(authentication);

                // 디버깅 로그
                System.out.println("JwtFilter: Authorization header = " + header);
                System.out.println("JwtFilter: Extracted role = " + role);
                System.out.println("JwtFilter: Granted authorities = " + authorities);
            }
        }

        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        return path.startsWith("/api/login")
                || path.startsWith("/api/register")
                || path.startsWith("/api/refresh")
                || path.startsWith("/api/google-login"); // 구글 로그인도 예외처리 필요
    }
}

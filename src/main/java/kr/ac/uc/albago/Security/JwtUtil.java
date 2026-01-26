package kr.ac.uc.albago.Security;

import io.jsonwebtoken.Claims; // 이거 추가
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;

    private SecretKey secretKey;

    @PostConstruct
    public void init() {
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes());
    }
//
//    // JWT 토큰 생성 (username, role, companyId 포함)
//    public String generateToken(String username, String role, String companyId, int minutes) {
//        return Jwts.builder()
//                .setSubject(username)
//                .claim("role", "ROLE_" + role.toUpperCase())
//                .claim("companyId", companyId)
//                .setIssuedAt(new Date())
//                .setExpiration(new Date(System.currentTimeMillis() + minutes * 60 * 1000))
//                .signWith(secretKey, SignatureAlgorithm.HS256)
//                .compact();
//    }
// JwtUtil.java
public String generateAccessToken(String email, String role, String companyId, int minutes) {
    return Jwts.builder()
            .setSubject(email)
            .claim("type", "ACCESS")
            .claim("role", role.toLowerCase())
            .claim("companyId", companyId)
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + minutes * 60L * 1000L))
            .signWith(secretKey, SignatureAlgorithm.HS256)
            .compact();
}

    public String generateRefreshToken(String email, int days) {
        return Jwts.builder()
                .setSubject(email)
                .claim("type", "REFRESH")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + days * 24L * 60L * 60L * 1000L))
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }

    public String extractTokenType(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .get("type", String.class);
    }

    public boolean isAccessToken(String token) {
        return "ACCESS".equals(extractTokenType(token));
    }

    public boolean isRefreshToken(String token) {
        return "REFRESH".equals(extractTokenType(token));
    }


    // companyId 추출
    public String extractCompanyId(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .get("companyId", String.class);
    }
    // 이메일(subject) 추출
    public String extractEmail(String token) {
        return extractAllClaims(token).getSubject();
    }

    // role 추출
    public String extractRole(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .get("role", String.class);
    }

    // 토큰 유효성 검사
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }


    // 모든 클레임 추출
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}

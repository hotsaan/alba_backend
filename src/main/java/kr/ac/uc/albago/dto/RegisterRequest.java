package kr.ac.uc.albago.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public class RegisterRequest {

    @JsonProperty("isPartial")   // ⭐ JSON 키 매핑
    private Boolean partial;

    private String email;
    private String password;
    private String username;
    private String role;

    public Boolean getPartial() {
        return partial;
    }
    public void setPartial(Boolean partial) {
        this.partial = partial;
    }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }
}

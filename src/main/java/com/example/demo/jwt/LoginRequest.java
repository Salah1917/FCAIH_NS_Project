package com.example.demo.jwt;

import lombok.Setter;

@Setter
public class LoginRequest {
    private String username;

    private String password;

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }
}

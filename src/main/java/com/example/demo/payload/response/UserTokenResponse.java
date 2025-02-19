package com.example.demo.payload.response;

import com.example.demo.entity.User;
import lombok.Data;

@Data
public class UserTokenResponse {
    private User user;
    private String token;
    
    public UserTokenResponse(User user, String token) {
        this.user = user;
        this.token = token;
    }
}

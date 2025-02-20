package com.example.demo.payload.request;

import javax.validation.constraints.Email;
import javax.validation.constraints.Size;
import lombok.Data;

@Data
public class UpdateUserRequest {
    @Size(max = 50)
    private String username;
    
    @Size(max = 50)
    @Email
    private String email;
    
    @Size(min = 6, max = 40)
    private String password;
}

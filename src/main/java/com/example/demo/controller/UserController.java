package com.example.demo.controller;

import com.example.demo.entity.User;
import com.example.demo.payload.request.TokenRequest;
import com.example.demo.payload.request.UpdateUserRequest;
import com.example.demo.payload.response.UserTokenResponse;
import com.example.demo.payload.response.MessageResponse;
import com.example.demo.repository.UserRepository;
import com.example.demo.security.jwt.JwtUtils;
import com.example.demo.security.services.UserDetailsServiceImpl;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.List;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@Tag(name = "User", description = "User management APIs")
public class UserController {
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    UserDetailsServiceImpl userDetailsService;
    
    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    PasswordEncoder passwordEncoder;
    
    @Operation(summary = "Get all users", description = "Returns a list of all users")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Successfully retrieved users",
            content = @Content(mediaType = "application/json", schema = @Schema(implementation = User.class))),
        @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @GetMapping("/users")
    @PreAuthorize("isAuthenticated() and hasRole('ADMIN')")
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }
    
    @Operation(summary = "Get user by ID", description = "Returns a user by ID")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Successfully retrieved user",
            content = @Content(mediaType = "application/json", schema = @Schema(implementation = User.class))),
        @ApiResponse(responseCode = "404", description = "User not found"),
        @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @GetMapping("/users/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> getUserById(
        @Parameter(description = "ID of the user to retrieve") @PathVariable String id
    ) {
        try {
            User user = userDetailsService.getUserById(id);
            return ResponseEntity.ok(user);
        } catch (UsernameNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(e.getMessage());
        }
    }
    
    @Operation(summary = "Update user by ID", description = "Updates a user's information by their ID")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Successfully updated user",
            content = @Content(mediaType = "application/json", schema = @Schema(implementation = User.class))),
        @ApiResponse(responseCode = "404", description = "User not found"),
        @ApiResponse(responseCode = "400", description = "Invalid input"),
        @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PutMapping("/users/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> updateUser(
        @Parameter(description = "ID of the user to update") @PathVariable String id,
        @Parameter(description = "Updated user information") @Valid @RequestBody UpdateUserRequest updateRequest
    ) {
        try {
            User existingUser = userDetailsService.getUserById(id);
            
            if (updateRequest.getUsername() != null) {
                // Check if new username is already taken
                if (userRepository.existsByUsername(updateRequest.getUsername()) && 
                    !existingUser.getUsername().equals(updateRequest.getUsername())) {
                    return ResponseEntity.badRequest()
                        .body(new MessageResponse("Username is already taken!"));
                }
                existingUser.setUsername(updateRequest.getUsername());
            }
            
            if (updateRequest.getEmail() != null) {
                // Check if new email is already taken
                if (userRepository.existsByEmail(updateRequest.getEmail()) && 
                    !existingUser.getEmail().equals(updateRequest.getEmail())) {
                    return ResponseEntity.badRequest()
                        .body(new MessageResponse("Email is already taken!"));
                }
                existingUser.setEmail(updateRequest.getEmail());
            }
            
            if (updateRequest.getPassword() != null) {
                existingUser.setPassword(passwordEncoder.encode(updateRequest.getPassword()));
            }
            
            User updatedUser = userRepository.save(existingUser);
            return ResponseEntity.ok(updatedUser);
            
        } catch (UsernameNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new MessageResponse("User not found"));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new MessageResponse("Error updating user: " + e.getMessage()));
        }
    }
    
    @Operation(summary = "Fetch user by token (POST)", description = "Returns user information using JWT token from request body")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Successfully retrieved user",
            content = @Content(mediaType = "application/json", schema = @Schema(implementation = UserTokenResponse.class))),
        @ApiResponse(responseCode = "401", description = "Invalid or expired token"),
        @ApiResponse(responseCode = "404", description = "User not found")
    })
    @PostMapping("/users/fetch-by-token")
    public ResponseEntity<?> fetchUserByToken(
        @Parameter(description = "Token request object containing JWT token")
        @Valid @RequestBody TokenRequest tokenRequest
    ) {
        return fetchUserWithToken(tokenRequest.getToken());
    }
    
    @Operation(summary = "Fetch user by token (GET)", description = "Returns user information using JWT token from query parameter")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Successfully retrieved user",
            content = @Content(mediaType = "application/json", schema = @Schema(implementation = UserTokenResponse.class))),
        @ApiResponse(responseCode = "401", description = "Invalid or expired token"),
        @ApiResponse(responseCode = "404", description = "User not found")
    })
    @GetMapping("/users/fetch-by-token")
    public ResponseEntity<?> fetchUserByTokenParam(
        @Parameter(description = "JWT token") @RequestParam String token
    ) {
        return fetchUserWithToken(token);
    }
    
    private ResponseEntity<?> fetchUserWithToken(String token) {
        try {
            if (!jwtUtils.validateJwtToken(token)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body("Invalid or expired token");
            }
            
            String username = jwtUtils.getUserNameFromJwtToken(token);
            
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));
            
            UserTokenResponse response = new UserTokenResponse(user, token);
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error fetching user details: " + e.getMessage());
        }
    }
}

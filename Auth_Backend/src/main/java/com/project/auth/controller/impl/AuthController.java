package com.project.auth.controller.impl;

import com.project.auth.controller.IAuthController;
import com.project.auth.dto.AuthReponse;
import com.project.auth.dto.AuthRequest;
import com.project.auth.dto.RegisterRequest;
import com.project.auth.service.IAuthService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController implements IAuthController {

    @Autowired
    private IAuthService authService;


    @Override
    @PostMapping("/register")
    public AuthReponse registerUser(@RequestBody @Valid RegisterRequest registerRequest) {
        return authService.registerUser(registerRequest);
    }

    @Override
    @PostMapping("/authenticate")
    public AuthReponse authenticate(@RequestBody AuthRequest authRequest) {
        return authService.authenticate(authRequest);
    }

    @Override
    @PostMapping("/refreshAccessToken")
    public AuthReponse refreshAccessToken(@RequestBody String tokenStr) {
        return authService.refreshAccessToken(tokenStr);
    }
}

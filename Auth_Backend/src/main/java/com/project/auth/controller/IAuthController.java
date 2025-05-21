package com.project.auth.controller;

import com.project.auth.dto.AuthReponse;
import com.project.auth.dto.AuthRequest;
import com.project.auth.dto.RegisterRequest;

public interface IAuthController {
    public AuthReponse registerUser(RegisterRequest registerRequest);

    public AuthReponse authenticate(AuthRequest authRequest);

    public AuthReponse refreshAccessToken(String tokenStr);

}

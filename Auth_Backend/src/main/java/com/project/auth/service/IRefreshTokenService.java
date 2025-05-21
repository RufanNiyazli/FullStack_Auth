package com.project.auth.service;

import com.project.auth.entity.RefreshToken;
import com.project.auth.entity.User;

public interface IRefreshTokenService {

    public RefreshToken createRefreshToken(User user);
    public RefreshToken validateRefreshToken(String token);
}

package com.project.auth.service.impl;

import com.project.auth.entity.RefreshToken;
import com.project.auth.entity.User;
import com.project.auth.exception.BaseException;
import com.project.auth.exception.MessageType;
import com.project.auth.repository.RefreshTokenRepository;
import com.project.auth.service.IRefreshTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.UUID;

@Service
public class RefreshTokenService implements IRefreshTokenService {

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;


    @Override
    public RefreshToken createRefreshToken(User user) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setCreatedAt(new Date());
        refreshToken.setExpiredAt(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 2));
        refreshToken.setRevoked(false);
        refreshToken.setUser(user);


        return refreshToken;
    }

    @Override
    public RefreshToken validateRefreshToken(String tokenStr) {

        RefreshToken token = refreshTokenRepository.findByToken(tokenStr).orElseThrow(() -> new RuntimeException("RefreshToken not found!"));

        if (token.getExpiredAt().before(new Date())) {

            throw new BaseException(MessageType.EXPIRED_TOKEN, "Refresh token müddəti bitib");
        }
        if (token.isRevoked()) {
            token.setRevoked(true); // Müddəti bitibsə revoked true edilir
            refreshTokenRepository.save(token); // DB-də yenilənir
            throw new BaseException(MessageType.INVALID_TOKEN, "Refresh token ləğv edilib");
        }

        return token;
    }
}

package com.project.auth.service.impl;

import com.project.auth.dto.AuthReponse;
import com.project.auth.dto.AuthRequest;

import com.project.auth.dto.RegisterRequest;

import com.project.auth.entity.RefreshToken;
import com.project.auth.entity.User;
import com.project.auth.exception.BaseException;
import com.project.auth.exception.MessageType;
import com.project.auth.repository.RefreshTokenRepository;
import com.project.auth.repository.UserRepository;
import com.project.auth.security.JwtService;
import com.project.auth.service.IAuthService;
import org.apache.tomcat.util.net.openssl.ciphers.Authentication;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.naming.AuthenticationException;
import java.util.Optional;

@Service
public class AuthServiceImpl implements IAuthService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RefreshTokenService refreshTokenService;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private RefreshTokenRepository refreshTokenRepository;
    @Autowired
    private BCryptPasswordEncoder passwordEncoder;


    @Override
    public AuthReponse registerUser(RegisterRequest registerRequest) {
        if (userRepository.existsByUsername(registerRequest.getUsername())) {
            throw new BaseException(MessageType.NO_RECORD_EXIST, "Bu istifadəçi adı artıq mövcuddur");
        }

        User user = User.builder().username(registerRequest.getUsername()).email(registerRequest.getEmail()).password(passwordEncoder.encode(registerRequest.getPassword())).role("USER").build();

//        BeanUtils.copyProperties(registerRequest, user);
        User dbUser = userRepository.save(user);

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(dbUser);
        String accessToken = jwtService.generateToken(dbUser);

        refreshTokenRepository.save(refreshToken);


        return new AuthReponse(accessToken, refreshToken.getToken());
    }

    @Override
    public AuthReponse authenticate(AuthRequest authRequest) {


        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));
        } catch (BadCredentialsException e) {
            throw new BaseException(MessageType.GENERAL_EXCEPTION, "Yanlış istifadəçi adı və ya şifrə");
        }
        Optional<User> optionalUser = userRepository.findByUsername(authRequest.getUsername());
        if (optionalUser.isEmpty()) {
            throw new BaseException(MessageType.NO_RECORD_EXIST);
        }

        String accessToken = jwtService.generateToken(optionalUser.get());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(optionalUser.get());


        refreshTokenRepository.save(refreshToken);

        return new AuthReponse(accessToken, refreshToken.getToken());

    }

    @Override
    public AuthReponse refreshAccessToken(String tokenStr) {

        RefreshToken refreshToken = refreshTokenService.validateRefreshToken(tokenStr);
        User user = refreshToken.getUser();
        String newAccessToken = jwtService.generateToken(user);


        return new AuthReponse(newAccessToken, refreshToken.getToken());
    }


}

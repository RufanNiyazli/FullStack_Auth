//package com.project.auth.entity;
//
//import com.fasterxml.jackson.annotation.JsonFormat;
//import jakarta.persistence.*;
//import lombok.AllArgsConstructor;
//import lombok.Data;
//import lombok.NoArgsConstructor;
//
//import java.util.Date;
//import java.util.List;
//
//@Entity
//@Table(name = "access_tokens")
//@Data
//@NoArgsConstructor
//@AllArgsConstructor
//public class AccessToken {
//    @Id
//    @GeneratedValue(strategy = GenerationType.IDENTITY)
//    private Long id;
//
//    @Column(nullable = false, unique = true)
//    private String token;
//
//    @Column(name = "created_at")
//    private Date createdAt;
//
//    @Column(name = "expired_at")
//    private Date expiredAt;
//
//    private boolean revoked = false;
//
//    @ManyToOne
//    @JoinColumn(name = "refresh_token_id")
//    private RefreshToken refreshToken;
//}

package com.example.userservice.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class TokenUtil {

    private static Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());

    public static Map<String, String> createToken(String issuer, User user){

        //Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
        String access_token = JWT.create()
                .withSubject(user.getUsername()) // user id 와 같이 사용자를 식별할 수 있는 값을 넘긴다.
                .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000)) // 만료일 설정
                .withIssuer(issuer) // JWT 만든 url 정의
                .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList())) // role 정의
                .sign(algorithm);

        String refresh_token = JWT.create()
                .withSubject(user.getUsername()) // user id 와 같이 사용자를 식별할 수 있는 값을 넘긴다.
                .withExpiresAt(new Date(System.currentTimeMillis() + 30 * 60 * 1000))
                .withIssuer(issuer)
                .sign(algorithm);
        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", access_token);
        tokens.put("refresh_token", refresh_token);

        return tokens;

    }




}

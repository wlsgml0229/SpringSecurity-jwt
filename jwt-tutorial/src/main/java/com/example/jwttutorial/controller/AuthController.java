package com.example.jwttutorial.controller;

import com.example.jwttutorial.dto.LoginDto;
import com.example.jwttutorial.dto.TokenDto;
import com.example.jwttutorial.jwt.JwtFilter;
import com.example.jwttutorial.jwt.TokenProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
@RequestMapping("/api")
public class AuthController {
    private final TokenProvider tokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    public AuthController(TokenProvider tokenProvider, AuthenticationManagerBuilder authenticationManagerBuilder) {
        this.tokenProvider = tokenProvider;
        this.authenticationManagerBuilder = authenticationManagerBuilder;
    }

    @PostMapping("/authenticate")
    public ResponseEntity<TokenDto> authorize(@Valid @RequestBody LoginDto loginDto) {
        //usedrname, userpassword파라미터로 authenticationtoken 객체를 생성
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());

        //authenticationToken을 가지고 authenticate메소드를 실행하게 되면
        // --> CustomUserDetailsService의 loadByUsername이 실행
        //결과값을 가지고 authentication 객체를 생성하게 됨
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);

        //authentication을 SecurityContext에 저장
        SecurityContextHolder.getContext().setAuthentication(authentication);

        //authentication을 가지고 jwt 토큰을 생성.
        String jwt = tokenProvider.createToken(authentication);

        //jwt를 responseHeader, responseBody 에 넣어 리턴
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(JwtFilter.AUTHORIZATION_HEADER, "Bearer " + jwt);

        return new ResponseEntity<>(new TokenDto(jwt), httpHeaders, HttpStatus.OK);
    }
}

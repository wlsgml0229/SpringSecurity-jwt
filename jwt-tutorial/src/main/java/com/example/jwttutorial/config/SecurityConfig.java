package com.example.jwttutorial.config;

import com.example.jwttutorial.jwt.JwtAccessDeniedHandler;
import com.example.jwttutorial.jwt.JwtAuthenticationEntryPoint;
import com.example.jwttutorial.jwt.JwtSecurityConfig;
import com.example.jwttutorial.jwt.TokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity //기본적인 웹 보안 활성화
@EnableGlobalMethodSecurity(prePostEnabled = true) //@PreAuthorize 어노테이션을 메소드단위로 추가하기 위해 적용
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    public SecurityConfig(
            TokenProvider tokenProvider,
            JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
            JwtAccessDeniedHandler jwtAccessDeniedHandler
    ) {
        this.tokenProvider = tokenProvider;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(WebSecurity web) {
        web
                .ignoring()
                .antMatchers(
                        "/h2-console/**"
                        , "/favicon.ico"
                );
    }


    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                //token 방식을 사용하므로 csrf 설정을 disable
                .csrf().disable()

                //예외처리를 위해 만들었던 코드를 지정
                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)

                //데이터확인을 위해 사용하고 있는 h2-console을 위한 설정을 추가
               .and()
                .headers()
                .frameOptions()
                .sameOrigin()

                //세션을 사용하지 않기 때문에 세션 설정을 STATELESS로 지정
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                ///api/hello, /api/authenticate, /api/signup 3가지 API는 Token이 없어도 호출할 수 있도록 허용
                .and()
                .authorizeRequests() //HttpServletRequest 를 사용하는 요청들에 대한 접근제한
                .antMatchers("/api/hello").permitAll() //api요청에대한 인증없이
                .antMatchers("/api/authenticate").permitAll()
                .antMatchers("/api/signup").permitAll()
                .anyRequest().authenticated()

                //위에서 만들었던 JwtFilter를 addFilterBefore 메소드로 등록했던 JwtSecurityConfig 클래스도 적용
                .and()
                .apply(new JwtSecurityConfig(tokenProvider));
    }
}

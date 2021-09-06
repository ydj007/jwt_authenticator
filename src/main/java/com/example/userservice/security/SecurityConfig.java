package com.example.userservice.security;

import com.example.userservice.filter.CustomAuthenticationFilter;
import com.example.userservice.filter.CustomAuthorizationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

@Configuration @EnableWebSecurity @RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final UserDetailsService userDetailsService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    // AuthenticationManagerBuilder 를 사용하여 사용자 인증하는 것이 일반적인 방식이다.
    // userDetailsService 는 JPA 에서 주로 사용하는 방식이고 JDBC, LDAP 등 인증 도구도 제공된다.
    // 그런데 JWT 토큰으로 authentication 하려면 custom http filter를 추가해서 authentication 방식을 커스텀해야 한다.
    // 굳이 이런 어려운 방식으로 JWT를 구현해야 하나 싶다.
    // 왜 내장이 안되어 있을까
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(authenticationManagerBean()); // AuthenticationFilter의 기본 url을 변경하려면 오버라이드를 해야 한다.
        customAuthenticationFilter.setFilterProcessesUrl("/api/login"); // login url 변경하기
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.authorizeRequests().antMatchers("/api/login/**", "/api/token/refresh/**").permitAll(); // custom login url override 했을 때, 순서가 중요하다.
        //http.authorizeRequests().antMatchers("/login").permitAll(); // default filter 의 url 사용할 때
        http.authorizeRequests().antMatchers(GET,"/api/user/**").hasAnyAuthority("ROLE_USER"); // ROLE_USER 권한이 있는 경우에만 허용
        http.authorizeRequests().antMatchers(POST,"/api/user/save/**").hasAnyAuthority("ROLE_ADMIN");
        http.authorizeRequests().anyRequest().authenticated(); // 모든 요청은 인증이 필요하다.
        //http.authorizeRequests().anyRequest().permitAll(); // 모든 요청을 authentication 없이 통과시킨다.
        //http.addFilter(new CustomAuthenticationFilter(authenticationManagerBean())); // 필터에 authenticationManager 클래스를 주입시켜야 하는데 추상 클래스에 있는 bean을 넣으면 된다.
        http.addFilter(customAuthenticationFilter);
        http.addFilterBefore(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception{
        return super.authenticationManagerBean();
    }
}

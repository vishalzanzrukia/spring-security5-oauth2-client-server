package com.security.oauth2.server.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

@EnableWebSecurity
public class DefaultSecurityConfig {
    private static PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable().cors().and().authorizeRequests().antMatchers("/**/articles/**","/mfa").authenticated()
                //.antMatchers("/mfa").hasAuthority("PRE_AUTH")
                .antMatchers("/**").permitAll()
                        .and().formLogin().loginPage("/login").successHandler(new SavedRequestAwareAuthenticationSuccessHandler()).and().oauth2ResourceServer().jwt();

        return http.build();
    }

    @Bean
    UserDetailsService users() {
        UserDetails user = User.builder()
                .username("admin")
                .password(passwordEncoder.encode("password"))
                .roles("USER")
                //.authorities("PRE_AUTH")
                .build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.mvcMatcher("/articles/**")
                .authorizeRequests()
                .mvcMatchers("/articles/**").permitAll()
                .and()
                .oauth2ResourceServer()
                .jwt();
        return http.build();
    }

}
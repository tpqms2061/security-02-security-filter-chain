package com.ssh.security_filter_chain.config;

import com.ssh.security_filter_chain.filter.FilterOrderLoggingFilter;
import com.ssh.security_filter_chain.filter.SecurityLoggingFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final SecurityLoggingFilter securityLoggingFilter;

    public SecurityConfig(SecurityLoggingFilter securityLoggingFilter) {
        this.securityLoggingFilter = securityLoggingFilter;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .addFilterBefore(
                        new FilterOrderLoggingFilter("CUSTOM-EARLY", 1),
                        UsernamePasswordAuthenticationFilter.class
                )
                .addFilterAfter(securityLoggingFilter, BasicAuthenticationFilter.class)
                .addFilterAfter(
                        new FilterOrderLoggingFilter("CUSTOM-LATE", 3),
                        securityLoggingFilter.getClass()
                )
                .authorizeHttpRequests(
                        auth -> auth
                                .requestMatchers("/public/**", "/css/**", "/js/**").permitAll()
                                .requestMatchers("/admin/**").hasRole("ADMIN")
                                .requestMatchers("/user/**").hasAnyRole("USER", "ADMIN")
                                .anyRequest().authenticated()
                )
                .formLogin(
                        form -> form
                                .loginPage("/login").permitAll()
                                .defaultSuccessUrl("/")
                                .failureUrl("/login?error=true")
                )
                .logout(
                        logout -> logout
                                .logoutUrl("/logout")
                                .logoutSuccessUrl("/login?logout=true")
                                .permitAll()
                )
                .httpBasic(basic -> {
                })
                .build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.builder().username("user").password(passwordEncoder().encode("password")).roles("USER").build();
        UserDetails admin = User.builder().username("admin").password(passwordEncoder().encode("admin")).roles("ADMIN","USER").build();
        return new InMemoryUserDetailsManager(user, admin);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

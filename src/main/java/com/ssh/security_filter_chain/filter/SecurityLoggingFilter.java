package com.ssh.security_filter_chain.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class SecurityLoggingFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(SecurityLoggingFilter.class);

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String requestURI = httpRequest.getRequestURI();
        String method = httpRequest.getMethod();

        // 🎬 요청 시작 로그
        logger.info("🎬 [REQUEST START] {} {}", method, requestURI);

        // 현재 인증 상태 확인
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated()) {
            logger.info("🔐 [AUTH STATUS] User: {}, Authorities: {}",
                    auth.getName(), auth.getAuthorities());
        } else {
            logger.info("👤 [AUTH STATUS] Not authenticated");
        }

        long startTime = System.currentTimeMillis();

        try {
            // 다음 필터로 요청 전달
            chain.doFilter(request, response);

            long endTime = System.currentTimeMillis();

            // 🏁 요청 완료 로그
            logger.info("🏁 [REQUEST END] {} {} -> Status: {}, Time: {}ms",
                    method, requestURI, httpResponse.getStatus(), (endTime - startTime));

        } catch (Exception e) {
            // ❌ 예외 발생 로그
            logger.error("❌ [REQUEST ERROR] {} {} -> Error: {}",
                    method, requestURI, e.getMessage());
            throw e;
        }
    }
}
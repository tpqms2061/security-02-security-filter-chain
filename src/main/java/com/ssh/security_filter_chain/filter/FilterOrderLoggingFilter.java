package com.ssh.security_filter_chain.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public class FilterOrderLoggingFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(FilterOrderLoggingFilter.class);
    private final String filterName;
    private final int order;

    public FilterOrderLoggingFilter(String filterName, int order) {
        this.filterName = filterName;
        this.order = order;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;

        // 🔍 필터 진입 로그
        logger.info("🔍 [FILTER-{}] {} BEFORE - URI: {}",
                order, filterName, httpRequest.getRequestURI());

        try {
            // 다음 필터 실행
            chain.doFilter(request, response);

            // ✅ 필터 완료 로그
            logger.info("✅ [FILTER-{}] {} AFTER", order, filterName);

        } catch (Exception e) {
            // ❌ 필터 예외 로그
            logger.error("❌ [FILTER-{}] {} ERROR: {}", order, filterName, e.getMessage());
            throw e;
        }
    }
}

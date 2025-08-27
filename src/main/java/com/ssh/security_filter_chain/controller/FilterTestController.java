package com.ssh.security_filter_chain.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class FilterTestController {

    private static final Logger logger = LoggerFactory.getLogger(FilterTestController.class);

    @GetMapping("/")
    public String home(Authentication authentication, Model model) {
        logger.info("🏠 [CONTROLLER] Home page accessed");
        if (authentication != null) {
            model.addAttribute("username", authentication.getName());
            model.addAttribute("authorities", authentication.getAuthorities());
        }
        return "home";
    }

    @GetMapping("/public/info")
    public String publicInfo() {
        logger.info("🌍 [CONTROLLER] Public info page accessed");
        return "public-info";
    }

    @GetMapping("/user/profile")
    public String userProfile(Authentication authentication, Model model) {
        logger.info("👤 [CONTROLLER] User profile accessed by: {}",
                authentication != null ? authentication.getName() : "unknown");
        if (authentication != null) {
            model.addAttribute("username", authentication.getName());
        }
        return "user-profile";
    }

    @GetMapping("/admin/dashboard")
    public String adminDashboard(Authentication authentication, Model model) {
        logger.info("👨‍💼 [CONTROLLER] Admin dashboard accessed by: {}",
                authentication != null ? authentication.getName() : "unknown");
        if (authentication != null) {
            model.addAttribute("username", authentication.getName());
        }
        return "admin-dashboard";
    }

    @GetMapping("/login")
    public String login() {
        logger.info("🔐 [CONTROLLER] Login page accessed");
        return "login";
    }
}

package ru.geekbrains.spring.security.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.management.remote.JMXAuthenticator;
import java.util.Arrays;

@Controller
public class WebController {
    private final AuthenticationManager authenticationManager;

    @Autowired
    public WebController(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @GetMapping("/public")
    public String publicPage() {
        return "publicPage";
    }

    @GetMapping("/private")
    public String privatePage() {
        return "privatePage";
    }

    @GetMapping("/login")
    public String login() {

        return "login";
    }

    @GetMapping("/main")
    public String main(Model model, Authentication authentication) {
        if (authentication != null) {
            System.out.println(Arrays.toString(authentication.getAuthorities().stream().toArray()));

            if (authentication.getAuthorities().stream()
                    .anyMatch(r -> r.getAuthority().equals("ROLE_ADMIN"))) {
                System.out.println("Зашел админ");
                model.addAttribute("isAdmin", true);
                model.addAttribute("isUser", false);
            } else if (authentication.getAuthorities().stream()
                    .anyMatch(r -> r.getAuthority().equals("ROLE_USER"))) {
                System.out.println("Зашел user");
                model.addAttribute("isAdmin", false);
                model.addAttribute("isUser", true);

            } else {
                model.addAttribute("isAdmin", false);
                model.addAttribute("isUser", false);
            }
        } else {
                System.out.println("Nothing");
            }

        return "main";
    }

}
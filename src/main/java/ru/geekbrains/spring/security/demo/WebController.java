package ru.geekbrains.spring.security.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;

@Controller
public class WebController {
    private final AuthenticationManager authenticationManager;

    @Autowired
    public WebController(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    /**
     * Обработка запроса на публичную страницу
     * @return страница
     */
    @GetMapping("/public")
    public String publicPage() {
        return "publicPage";
    }

    /**
     * Обработка запроса на получение частной страницы
     * @return частная страница
     */
    @GetMapping("/private")
    public String privatePage() {
        return "privatePage";
    }

    /**
     * Обработка запроса на страницу аутентификации
     * @return страница аутентификации
     */
    @GetMapping("/login")
    public String login() {

        return "login";
    }

    /**
     * Обработка перехода на основную страницу
     * @param model модель страницы
     * @param authentication полученные параметры аутентификации
     * @return основную страницу, отображаемую в соответствии с аутентификацией
     */
    @GetMapping("/main")
    public String mainPage(Model model, Authentication authentication) {
        if (authentication != null) {
            System.out.println(Arrays.toString(authentication.getAuthorities().toArray()));

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
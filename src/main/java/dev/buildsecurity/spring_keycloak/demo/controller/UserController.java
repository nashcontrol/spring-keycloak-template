package dev.buildsecurity.spring_keycloak.demo.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/api/user")
public class UserController {

    @RequestMapping(value = "/anonymous", method = RequestMethod.GET)
    public ResponseEntity<String> getAnonymous() {
        return ResponseEntity.ok("Hello Anonymous user");
    }

    @PreAuthorize("hasRole('Reader')")
    @RequestMapping(value = "/me", method = RequestMethod.GET)
    public ResponseEntity<String> getUser(Authentication authentication) {
            return ResponseEntity.ok("Hello " + authentication.getName());
    }
    
}

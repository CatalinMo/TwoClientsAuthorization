package com.example.spring.AuthorizationServerApplication;


import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Collections;
import java.util.Map;

@RestController
public class UserController {

    @GetMapping("/user")
    public Principal user(Principal principal) {
        return principal;
    }

//    @GetMapping("/user")
//    public Map<String, Object> user(@AuthenticationPrincipal OAuth2User principal) {
//        return Collections.singletonMap("name", principal.getAttribute("name"));
//    }

//    @GetMapping("/alin")
//    public String getAlin(){return "<h1>Admin Alin</h1>";}
//
//   @GetMapping("/catalin")
//    public String getCatalin(){return "<h1>User Catalin</h1>";}

}
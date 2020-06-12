package com.southwind.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
//@CrossOrigin(origins = "http://localhost:8081")
@RestController
public class LoginController {
    @PostMapping("logins")
    public String logins(){
        return "成功";
    }
}

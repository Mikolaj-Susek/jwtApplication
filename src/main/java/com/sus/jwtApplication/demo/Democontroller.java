package com.sus.jwtApplication.demo;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/demo-controller")
public class Democontroller {

    @GetMapping()
    public ResponseEntity<String> checkController() {
        return ResponseEntity.ok("Controller is working correctly!!!");
    }
}

package com.acme.shop;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AdminController {

    @DeleteMapping("/actuator/health/{probe}")
    public void reset(@PathVariable String probe) {
    }
}

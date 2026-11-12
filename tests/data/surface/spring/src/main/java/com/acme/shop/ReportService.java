package com.acme.shop;

import java.io.IOException;
import org.springframework.stereotype.Service;

@Service
public class ReportService {

    public String export(String format) {
        try {
            Runtime.getRuntime().exec("report-tool --format " + format);
        } catch (IOException e) {
            return "error";
        }
        return "ok";
    }

    public Order store(OrderRequest body) {
        return new Order();
    }
}

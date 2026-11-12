package com.acme.shop;

import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/orders")
public class OrderController {

    private final JdbcTemplate jdbc;
    private final ReportService reports;

    public OrderController(JdbcTemplate jdbc, ReportService reports) {
        this.jdbc = jdbc;
        this.reports = reports;
    }

    @GetMapping("/{id}")
    public Order get(@PathVariable Long id, @RequestHeader("X-Tenant") String tenant) {
        return jdbc.queryForObject("SELECT * FROM orders WHERE id = ?", Order.class, id);
    }

    @GetMapping("/search")
    public List<Order> search(@RequestParam("q") String query, @RequestParam(required = false) String sort) {
        return jdbc.queryForList("SELECT * FROM orders WHERE note LIKE '%" + query + "%' ORDER BY " + sort, Order.class);
    }

    @PostMapping
    @PreAuthorize("hasRole('MANAGER')")
    public Order create(@RequestBody OrderRequest body) {
        return reports.store(body);
    }

    @RequestMapping(value = "/export", method = RequestMethod.GET)
    public String export(@RequestParam String format, @CookieValue("sid") String sid) {
        return reports.export(format);
    }

    @KafkaListener(topics = "orders.paid")
    public void onPaid(String message) {
        reports.export(message);
    }

    @Scheduled(cron = "0 0 * * * *")
    public void purge() {
        jdbc.update("DELETE FROM orders WHERE status = 'void'");
    }
}

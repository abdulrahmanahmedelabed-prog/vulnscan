package com.acme.billing;

import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/invoices")
public class InvoiceServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String invoice = request.getParameter("id");
        try (Connection c = DriverManager.getConnection("jdbc:postgresql://db/billing");
             Statement st = c.createStatement()) {
            ResultSet rs = st.executeQuery("SELECT * FROM invoices WHERE id = '" + invoice + "'");
            response.getWriter().println(rs.next() ? rs.getString("total") : "not found");
        } catch (SQLException e) {
            throw new IOException(e);
        }
    }
}

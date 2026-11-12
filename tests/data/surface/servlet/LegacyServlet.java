package com.acme.legacy;

import java.io.IOException;
import java.sql.Connection;
import java.sql.Statement;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(name = "legacy", urlPatterns = {"/legacy/report"})
public class LegacyServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("name");
        String agent = request.getHeader("User-Agent");
        try (Connection c = Db.open(); Statement st = c.createStatement()) {
            st.executeQuery("SELECT * FROM reports WHERE name = '" + name + "'");
        } catch (Exception e) {
            response.sendError(500);
        }
        response.getWriter().println(agent);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (request.getUserPrincipal() == null) {
            response.sendError(401);
            return;
        }
        response.sendRedirect(request.getParameter("next"));
    }
}

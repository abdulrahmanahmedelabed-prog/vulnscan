// expect-none: DF014
import static org.springframework.ldap.query.LdapQueryBuilder.query;

import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.support.LdapEncoder;
import javax.servlet.http.HttpServletRequest;

public class Auth {
    private LdapTemplate ldapTemplate;

    // authenticate(LdapQuery, password): argument 1 is the user's password, not an LDAP filter
    public void login(HttpServletRequest hreq) {
        String user = LdapEncoder.filterEncode(hreq.getParameter("user"));
        ldapTemplate.authenticate(query().where("uid").is(user), hreq.getParameter("password"));
    }
}

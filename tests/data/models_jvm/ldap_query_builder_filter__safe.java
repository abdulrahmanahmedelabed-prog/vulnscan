// expect-none: DF014
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.query.LdapQueryBuilder;
import javax.servlet.http.HttpServletRequest;

public class People {
    private LdapTemplate ldapTemplate;

    public Object find(HttpServletRequest hreq) {
        String cn = hreq.getParameter("cn");
        return ldapTemplate.find(LdapQueryBuilder.query().where("cn").is(cn), Object.class);
    }
}

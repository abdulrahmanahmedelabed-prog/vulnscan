// expect: DF014
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.SearchScope;
import javax.servlet.http.HttpServletRequest;

public class Directory {
    private LDAPConnection connection;

    public Object find(HttpServletRequest hreq) throws Exception {
        String user = hreq.getParameter("user");
        return connection.search("dc=example,dc=com", SearchScope.SUB, "(uid=" + user + ")");
    }
}

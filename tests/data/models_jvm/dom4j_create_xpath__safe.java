// expect-none: DF015
import org.dom4j.Document;
import org.dom4j.DocumentHelper;
import org.owasp.esapi.ESAPI;
import javax.servlet.http.HttpServletRequest;

public class Books {
    private Document doc;

    public Object find(HttpServletRequest hreq) {
        String title = ESAPI.encoder().encodeForXPath(hreq.getParameter("title"));
        return DocumentHelper.createXPath("//book[title='" + title + "']").selectNodes(doc);
    }
}

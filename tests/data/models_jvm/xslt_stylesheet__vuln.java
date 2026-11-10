// expect: DF012
import javax.servlet.http.HttpServletRequest;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamSource;
import java.io.StringReader;

public class Xslt {
    public Transformer build(HttpServletRequest hreq) throws Exception {
        TransformerFactory factory = TransformerFactory.newInstance();
        return factory.newTransformer(new StreamSource(new StringReader(hreq.getParameter("xsl"))));
    }
}

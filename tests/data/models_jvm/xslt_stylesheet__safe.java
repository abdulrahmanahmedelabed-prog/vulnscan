// expect-none: DF012
import javax.servlet.http.HttpServletRequest;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamSource;

public class Xslt {
    public Transformer build(HttpServletRequest hreq) throws Exception {
        TransformerFactory factory = TransformerFactory.newInstance();
        String theme = hreq.getParameter("theme");
        return factory.newTransformer(new StreamSource(getClass().getResourceAsStream("/xsl/report.xsl")));
    }
}

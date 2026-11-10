import io.jsonwebtoken.Jwts;
import com.auth0.jwt.algorithms.Algorithm;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.net.ssl.SSLContext;
import org.apache.http.conn.ssl.NoopHostnameVerifier;

public class Vuln {
    void run(String token, char[] pw, javax.net.ssl.HttpsURLConnection conn) throws Exception {
        // expect-next: JWT002
        Jwts.parser().unsecured().build();
        // expect-next: JWT002
        Object claims = Jwts.parser().parseClaimsJwt(token).getBody();
        // expect-next: JWT007
        Algorithm alg = Algorithm.HMAC256("hardcoded-secret");
        // expect-next: TLS002
        conn.setHostnameVerifier((hostname, session) -> true);
        // expect-next: TLS002
        Object v = NoopHostnameVerifier.INSTANCE;
        // expect-next: TLS006
        SSLContext ctx = SSLContext.getInstance("SSL");
        // expect-next: CRY007
        Cipher c = Cipher.getInstance("AES");
        // expect-next: CRY010
        IvParameterSpec iv = new IvParameterSpec(new byte[16]);
        // expect-next: CRY011
        PBEKeySpec spec = new PBEKeySpec(pw, "fixedsalt".getBytes(), 10000, 256);
    }

    // expect-next: CORS001
    @CrossOrigin(origins = "*", allowCredentials = "true")
    public String api() { return "ok"; }
}

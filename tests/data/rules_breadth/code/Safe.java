import io.jsonwebtoken.Jwts;
import com.auth0.jwt.algorithms.Algorithm;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.net.ssl.SSLContext;

public class Safe {
    void run(String token, char[] pw, byte[] salt, byte[] ivBytes, java.security.Key key,
             javax.net.ssl.HttpsURLConnection conn) throws Exception {
        Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
        Object claims = Jwts.parser().setSigningKey(key).parseClaimsJws(token).getBody();
        Algorithm alg = Algorithm.HMAC256(System.getenv("JWT_SECRET"));
        conn.setHostnameVerifier(javax.net.ssl.HttpsURLConnection.getDefaultHostnameVerifier());
        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        PBEKeySpec spec = new PBEKeySpec(pw, salt, 10000, 256);
    }

    @CrossOrigin(origins = "https://app.corp.internal", allowCredentials = "true")
    public String api() { return "ok"; }
}

using System.Net.Http;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

public class Vuln
{
    public void Configure(HttpClientHandler handler, SslOptions options, string password, CorsPolicyBuilder policy)
    {
        var parameters = new TokenValidationParameters
        {
            // expect-next: JWT005
            RequireSignedTokens = false,
            ValidateIssuerSigningKey = false,
            // expect-next: JWT005
            SignatureValidator = (token, p) => new JwtSecurityToken(token),
        };
        // expect-next: TLS003
        handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        // expect-next: TLS003
        System.Net.ServicePointManager.ServerCertificateValidationCallback += (s, cert, chain, errors) => true;
        // expect-next: TLS006
        options.EnabledSslProtocols = SslProtocols.Tls11;
        var aes = Aes.Create();
        // expect-next: CRY008
        aes.Mode = CipherMode.ECB;
        // expect-next: CRY010
        aes.IV = new byte[16];
        // expect-next: CRY009
        var des = new TripleDESCryptoServiceProvider();
        // expect-next: CRY011
        var kdf = new Rfc2898DeriveBytes(password, Encoding.UTF8.GetBytes("fixedsalt"), 100000, HashAlgorithmName.SHA256);
        // expect-next: CORS001
        policy.AllowAnyOrigin().AllowCredentials();
    }
}

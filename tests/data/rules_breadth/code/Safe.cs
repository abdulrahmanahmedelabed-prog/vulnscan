using System.Net.Http;
using System.Security.Authentication;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

public class Safe
{
    public void Configure(HttpClientHandler handler, SslOptions options, string password, byte[] salt, CorsPolicyBuilder policy)
    {
        var parameters = new TokenValidationParameters
        {
            RequireSignedTokens = true,
            ValidateIssuerSigningKey = false,
            SignatureValidator = CustomValidator.Validate,
        };
        handler.ServerCertificateCustomValidationCallback = ValidatePinnedCertificate;
        options.EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
        var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.IV = RandomNumberGenerator.GetBytes(16);
        var kdf = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256);
        policy.WithOrigins("https://app.corp.internal").AllowCredentials();
    }
}

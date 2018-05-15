using System;
using System.Security.Cryptography.X509Certificates;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using ClientConsole.Helpers;

namespace ClientConsole
{
    class Program
    {
        private const string X509ThumbPrint = "store=My;thumbprint=D0EAAFEAF821AC1C7D788D54BFAC3AD6F7DBC770";
        private static readonly X509Certificate2 ClientCertificate = CertificateHelper.GetCertificateFromThumbprint(X509ThumbPrint);

        static void Main(string[] args)
        {
            var token = CreateToken();
            Console.WriteLine(token);

            var securityToken = ValidateToken(token);
            Console.WriteLine(securityToken);
        }

        public static string CreateToken() {
            var securityKey = new X509SecurityKey(ClientCertificate);
            var header = new JwtHeader(new SigningCredentials(securityKey, "RS256"));

            var payload = new JwtPayload
            {
                {"iss", "issuer_id"},
                {"scope", "scope.com"},
                {"aud", "aud.com"},
                { "exp", (Int32)(DateTime.UtcNow.AddHours(20).Subtract(new DateTime(1970, 1, 1))).TotalSeconds},
                { "iat", (Int32)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds}
            };

            var jwtToken = new JwtSecurityToken(header, payload);
            var handler = new JwtSecurityTokenHandler();

            return handler.WriteToken(jwtToken);
        }

        public static SecurityToken ValidateToken(string tokenToValidate)
        {
            var handler = new JwtSecurityTokenHandler();
            SecurityToken token;
            
            try
            {
                ClaimsPrincipal principal = handler.ValidateToken(tokenToValidate, new TokenValidationParameters
                {
                    ValidIssuer = "issuer_id",
                    ValidAudience = "aud.com",
                    IssuerSigningKey = new X509SecurityKey(ClientCertificate),
                }, out token);
            }
            catch (Exception exception)
            {
                throw exception;
            }
            return token;
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace ClientConsole.Helpers
{
    static class CertificateHelper
    {
        internal static X509Certificate2 GetCertificateFromThumbprint(string clientCertificateInfo)
        {
            if (string.IsNullOrEmpty(clientCertificateInfo))
                return null;
            Dictionary<string, string> par = GetCertificateThumbprintParameters(clientCertificateInfo);

            return GetCertificateFromThumbprint(par);
        }

        private static X509Certificate2 GetCertificateFromThumbprint(Dictionary<string, string> clientCertificateInfo)
        {
            List<StoreLocation> locations = new List<StoreLocation>
            {
                StoreLocation.CurrentUser,
                StoreLocation.LocalMachine
            };

            foreach (var location in locations)
            {
                X509Store store = new X509Store(clientCertificateInfo["store"], location);
                store.Open(OpenFlags.ReadOnly);
                var cert = store.Certificates.OfType<X509Certificate2>()
                        .FirstOrDefault(x => x.Thumbprint.ToUpper() == clientCertificateInfo["thumbprint"].ToUpper());
                store.Close();
                if (cert != null)
                    return cert;
            }

            return null;
        }
        private static Dictionary<string, string> GetCertificateThumbprintParameters(string clientCertificateInfo)
        {
            Dictionary<string, string> dict = clientCertificateInfo.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries)
               .Select(part => part.Split('='))
               .ToDictionary(split => split[0], split => split[1]);

            return dict;
        }
    }
}

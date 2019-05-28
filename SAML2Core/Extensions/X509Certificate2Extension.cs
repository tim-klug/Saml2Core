
using System;
using System.Security.Cryptography.X509Certificates;


namespace SamlCore.AspNetCore.Authentication.Saml2
{
    public static class X509Certificate2Ext
    {
        public static X509Certificate2 GetX509Certificate2(
                string signingCertificateX509TypeValue,
                StoreName certificateStoreName = StoreName.My,
                StoreLocation certificateStoreLocation = StoreLocation.LocalMachine,
                X509FindType certificateIdentifierType = X509FindType.FindBySerialNumber)
        {
            X509Certificate2 x509Certificate = new X509Certificate2();
            using (var store = new X509Store(certificateStoreName, certificateStoreLocation))
            {
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection collection = store.Certificates.Find(certificateIdentifierType, signingCertificateX509TypeValue, true);
                store.Close();
                if (collection.Count == 0)
                {
                    throw new InvalidOperationException("Service Provider certificate could not be found.");
                }
                if (collection.Count > 1)
                {
                    throw new InvalidOperationException("Multiple Service Provider certificates were found, must only provide one.");
                }
                x509Certificate = collection[0];
                if (x509Certificate.PrivateKey == null)
                {
                    throw new InvalidOperationException("The certificate for this service providerhas no private key.");
                }
            }      
            return x509Certificate;
        }
    }
}
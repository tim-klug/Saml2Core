//MIT License

//Copyright (c) 2018 Dina Heidar

//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions:

//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.

//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.
using SamlCore.AspNetCore.Authentication.Saml2.Metadata;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SamlCore.AspNetCore.Authentication.Saml2
{
    /// <summary>
    /// 
    /// </summary>
    public class ServiceProviderInfo
    {
        /// <summary>
        /// Gets or sets the entity identifier.
        /// </summary>
        /// <value>
        /// The entity identifier.
        /// </value>
        public string EntityId { get; set; }
        
        /// <summary>
        /// Gets or sets the name of the certificate store.
        /// </summary>
        /// <value>
        /// The name of the certificate store.
        /// </value>
        public StoreName CertificateStoreName { get; set; }
        /// <summary>
        /// Gets or sets the certificate store location.
        /// </summary>
        /// <value>
        /// The certificate store location.
        /// </value>
        public StoreLocation CertificateStoreLocation { get; set; }
        /// <summary>
        /// Gets or sets the type of the certificate identifier.
        /// </summary>
        /// <value>
        /// The type of the certificate identifier.
        /// </value>
        public X509FindType CertificateIdentifierType { get; set; }
        /// <summary>
        /// Gets or sets the signing certificate X509 type value.
        /// </summary>
        /// <value>
        /// The signing certificate X509 type value.
        /// </value>
        public string SigningCertificateX509TypeValue { get; set; }
        /// <summary>
        /// Gets or sets the X509 certificate2.
        /// </summary>
        /// <value>
        /// The X509 certificate2.
        /// </value>
        public X509Certificate2 X509Certificate2 { get; set; }
        /// <summary>
        /// Gets or sets the hash algorithm. ADFS 2012 uses SHA1 or SHA256
        /// </summary>
        /// <value>
        /// The hash algorithm.
        /// </value>
        public HashAlgorithmName HashAlgorithm {get;set;}
        /// <summary>
        /// Gets or sets the name of the service provider name. This is is used the SP metadata file. This is optional.
        /// </summary>
        /// <value>
        /// The name of the service.
        /// </value>
        public string ServiceName { get; set; }
        /// <summary>
        /// Gets or sets the service provider service description. This is is used the SP metadata file. This is optional.
        /// </summary>
        /// <value>
        /// The service description.
        /// </value>
        public string ServiceDescription { get; set; }
        /// <summary>
        /// Gets or sets the language that is used in the service provider metadata.
        /// </summary>
        /// <value>
        /// The language.
        /// </value>
        public string Language { get; set; }

        /// <summary>
        /// Gets or sets the display name of the organization. This is used in the service provider metadata. This is optional. 
        /// </summary>
        /// <value>
        /// The display name of the organization.
        /// </value>
        public string OrganizationDisplayName { get; set; }
        /// <summary>
        /// Gets or sets the name of the organization. This is used in the service provider metadata. This is optional. 
        /// </summary>
        /// <value>
        /// The name of the organization.
        /// </value>
        public string OrganizationName { get; set; }
        /// <summary>
        /// Gets or sets the organization URL. This is used in the service provider metadata. This is optional. 
        /// </summary>
        /// <value>
        /// The organization URL.
        /// </value>
        public string OrganizationURL { get; set; }
        /// <summary>
        /// Gets or sets the contact person. This is used in the service provider metadata. This is optional. 
        /// </summary>
        /// <value>
        /// The contact person.
        /// </value>
        public ContactType ContactPerson { get; set; } = new ContactType();
    }
}
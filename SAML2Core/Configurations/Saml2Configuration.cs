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
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Xml;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace SamlCore.AspNetCore.Authentication.Saml2
{
    /// <summary>
    /// 
    /// </summary>
    public class Saml2Configuration
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Saml2Configuration"/> class.
        /// </summary>
        public Saml2Configuration(){}
        /// <summary>
        /// Gets or sets the X509 certificate2.
        /// </summary>
        /// <value>
        /// The X509 certificate2.
        /// </value>
        public ICollection<X509Certificate2> X509Certificate2 { get; set; } = new List<X509Certificate2>();
        /// <summary>
        /// Gets or sets the issuer.
        /// </summary>
        /// <value>
        /// The issuer.
        /// </value>
        public string Issuer { get; set; }
        /// <summary>
        /// Gets the signing keys.
        /// </summary>
        /// <value>
        /// The signing keys.
        /// </value>
        public ICollection<SecurityKey> SigningKeys { get; } = new List<SecurityKey>();
        /// <summary>
        /// Gets or sets the signature.
        /// </summary>
        /// <value>
        /// The signature.
        /// </value>
        public Signature Signature { get; set; }
        /// <summary>
        /// Gets or sets the signing credentials.
        /// </summary>
        /// <value>
        /// The signing credentials.
        /// </value>
        public SigningCredentials SigningCredentials { get; set; }
        /// <summary>
        /// Gets the key infos.
        /// </summary>
        /// <value>
        /// The key infos.
        /// </value>
        public ICollection<KeyInfo> KeyInfos { get; } = new List<KeyInfo>();
        /// <summary>
        /// Gets or sets the token endpoint.
        /// </summary>
        /// <value>
        /// The token endpoint.
        /// </value>
        public string TokenEndpoint { get; set; }
        /// <summary>
        /// Gets or sets the name identifier format.
        /// </summary>
        /// <value>
        /// The name identifier format.
        /// </value>
        public ICollection<string> NameIdFormat { get; set; }   
        
        //public string 
        /// <summary>
        /// Gets or sets the single sign on services.
        /// </summary>
        /// <value>
        /// The single sign on services.
        /// </value>
        public ICollection<LocationWithBinding> SingleSignOnServices { get; set; }
        /// <summary>
        /// Gets or sets the single logout services.
        /// </summary>
        /// <value>
        /// The single logout services.
        /// </value>
        public ICollection<LocationWithBinding> SingleLogoutServices { get; set; }       
    }    
}
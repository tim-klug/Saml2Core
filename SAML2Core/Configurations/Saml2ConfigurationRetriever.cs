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
using Microsoft.IdentityModel.Protocols;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using static Microsoft.IdentityModel.Logging.LogHelper;

namespace SamlCore.AspNetCore.Authentication.Saml2
{
    /// <summary>
    /// 
    /// </summary>  
    public class Saml2ConfigurationRetriever : IConfigurationRetriever<Saml2Configuration>
    {
#if NETSTANDARD1_4
                private static readonly XmlReaderSettings SafeSettings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit };
#else
        /// <summary>
        /// The safe settings
        /// </summary>
        private static readonly XmlReaderSettings SafeSettings = new XmlReaderSettings { XmlResolver = null, DtdProcessing = DtdProcessing.Prohibit, ValidationType = ValidationType.None };
#endif

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml2ConfigurationRetriever"/> class.
        /// </summary>
        public Saml2ConfigurationRetriever() { }

        /// <summary>
        /// Gets the asynchronous.
        /// </summary>
        /// <param name="address">The address.</param>
        /// <param name="cancel">The cancel.</param>
        /// <returns></returns>
        public static Task<Saml2Configuration> GetAsync(string address, CancellationToken cancel)
        {
            if (string.IsNullOrEmpty(address))
                throw LogArgumentNullException(nameof(address));

            return GetAsync(address, new HttpDocumentRetriever(), cancel);
        }

        /// <summary>
        /// Gets the asynchronous.
        /// </summary>
        /// <param name="address">The address.</param>
        /// <param name="httpClient">The HTTP client.</param>
        /// <param name="cancel">The cancel.</param>
        /// <returns></returns>
        public static Task<Saml2Configuration> GetAsync(string address, HttpClient httpClient, CancellationToken cancel)
        {
            if (string.IsNullOrEmpty(address))
                throw LogArgumentNullException(nameof(address));

            if (httpClient == null)
                throw LogArgumentNullException(nameof(httpClient));

            return GetAsync(address, new HttpDocumentRetriever(httpClient), cancel);
        }

        /// <summary>
        /// Retrieves a populated configuration given an address and an <see cref="T:Microsoft.IdentityModel.Protocols.IDocumentRetriever" />.
        /// </summary>
        /// <param name="address">Address of the discovery document.</param>
        /// <param name="retriever">The <see cref="T:Microsoft.IdentityModel.Protocols.IDocumentRetriever" /> to use to read the discovery document.</param>
        /// <param name="cancel">A cancellation token that can be used by other objects or threads to receive notice of cancellation. <see cref="T:System.Threading.CancellationToken" />.</param>
        /// <returns></returns>
        Task<Saml2Configuration> IConfigurationRetriever<Saml2Configuration>.GetConfigurationAsync(string address, IDocumentRetriever retriever, CancellationToken cancel)
        {
            return GetAsync(address, retriever, cancel);
        }

        /// <summary>
        /// Gets the asynchronous.
        /// </summary>
        /// <param name="address">The address.</param>
        /// <param name="retriever">The retriever.</param>
        /// <param name="cancel">The cancel.</param>
        /// <returns></returns>
        public static async Task<Saml2Configuration> GetAsync(string address, IDocumentRetriever retriever, CancellationToken cancel)
        {
            if (string.IsNullOrEmpty(address))
                throw LogArgumentNullException(nameof(address));

            if (retriever == null)
                throw LogArgumentNullException(nameof(retriever));

            string document = await retriever.GetDocumentAsync(address, cancel).ConfigureAwait(false);
            
            using (var metaDataReader = XmlReader.Create(new StringReader(document), SafeSettings))
            {
              return (new Saml2MetadataSerializer()).ReadMetadata(metaDataReader);
            }
        }
    }
}
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
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using SamlCore.AspNetCore.Authentication.Saml2.Metadata;
using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Xml;
using System.Xml.Serialization;

namespace SamlCore.AspNetCore.Authentication.Saml2
{
    /// <summary>
    /// Used to setup defaults for all <see cref="Saml2Options" />.
    /// </summary>  
    public class Saml2PostConfigureOptions : IPostConfigureOptions<Saml2Options>
    {
        /// <summary>
        /// The idoc
        /// </summary>
        private readonly IDocumentRetriever _idoc;
        /// <summary>
        /// The dp
        /// </summary>
        private readonly IDataProtectionProvider _dp;
        /// <summary>
        /// The HTTP context accessor
        /// </summary>
        private readonly IHttpContextAccessor _httpContextAccessor;

        /// <summary>
        /// Gets the safe settings.
        /// </summary>
        /// <value>
        /// The safe settings.
        /// </value>
        public static XmlReaderSettings SafeSettings { get; private set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml2PostConfigureOptions" /> class.
        /// </summary>
        /// <param name="dataProtection">The data protection.</param>
        /// <param name="idoc">The idoc.</param>
        /// <param name="httpContextAccessor">The HTTP context accessor.</param>
        public Saml2PostConfigureOptions(IDataProtectionProvider dataProtection, IDocumentRetriever idoc, IHttpContextAccessor httpContextAccessor)
        {
            _dp = dataProtection;
            _idoc = idoc;
            _httpContextAccessor = httpContextAccessor;
        }

        /// <summary>
        /// Invoked to post configure a TOptions instance.
        /// </summary>
        /// <param name="name">The name of the options instance being configured.</param>
        /// <param name="options">The options instance to configure.</param>
        /// <exception cref="InvalidOperationException">
        /// Service Provider certificate could not be found.
        /// or
        /// Multiple Service Provider certificates were found, must only provide one.
        /// or
        /// The certificate for this service providerhas no private key.
        /// or
        /// The MetadataAddress must use HTTPS unless disabled for development by setting RequireHttpsMetadata=false.
        /// </exception>
        public void PostConfigure(string name, Saml2Options options)
        {
            options.DataProtectionProvider = options.DataProtectionProvider ?? _dp;

            if (string.IsNullOrEmpty(options.SignOutScheme))
            {
                options.SignOutScheme = options.SignInScheme;
            }

            if (options.StateDataFormat == null)
            {
                var dataProtector = options.DataProtectionProvider.CreateProtector(
                    typeof(Saml2Handler).FullName, name, "v1");
                options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }

            if (options.ServiceProvider.ApplicationProductionURL != null)
            {
                Uri uriAppUrlResult;
                bool appProductionURLresult = Uri.TryCreate(options.ServiceProvider.ApplicationProductionURL, UriKind.Absolute, out uriAppUrlResult)
                    && (uriAppUrlResult.Scheme == Uri.UriSchemeHttp || uriAppUrlResult.Scheme == Uri.UriSchemeHttps);

                if (!appProductionURLresult)
                {
                    throw new InvalidOperationException("ApplicationProductionURL is not a valid URL.");
                }
                else
                {
                    var baseProductionUri = new Uri(options.ServiceProvider.ApplicationProductionURL);
                    options.AssertionURL_PRD = new Uri(baseProductionUri, options.CallbackPath).AbsoluteUri;
                    options.SignOutURL_PRD = new Uri(baseProductionUri, options.SignOutPath).AbsoluteUri;
                }
            }

            if (options.ServiceProvider.ApplicationStageURL != null)
            {
                Uri uriAppUrlResult;
                bool appStageURLresult = Uri.TryCreate(options.ServiceProvider.ApplicationStageURL, UriKind.Absolute, out uriAppUrlResult)
                    && (uriAppUrlResult.Scheme == Uri.UriSchemeHttp || uriAppUrlResult.Scheme == Uri.UriSchemeHttps);

                if (!appStageURLresult)
                {
                    throw new InvalidOperationException("ApplicationStageURL is not a valid URL.");
                }
                else
                {
                    var baseStageUri = new Uri(options.ServiceProvider.ApplicationStageURL);
                    options.AssertionURL_STG = new Uri(baseStageUri, options.CallbackPath).AbsoluteUri;
                    options.SignOutURL_STG= new Uri(baseStageUri, options.SignOutPath).AbsoluteUri;
                }
            }
            if (!string.IsNullOrEmpty(options.ServiceProvider.SigningCertificateX509TypeValue))
            {
                using (var store = new X509Store(options.ServiceProvider.CertificateStoreName, options.ServiceProvider.CertificateStoreLocation))
                {
                    store.Open(OpenFlags.ReadOnly);
                    X509Certificate2Collection collection = store.Certificates.Find(options.ServiceProvider.CertificateIdentifierType, options.ServiceProvider.SigningCertificateX509TypeValue, true);
                    store.Close();
                    if (collection.Count == 0)
                    {
                        throw new InvalidOperationException("Service Provider certificate could not be found.");
                    }
                    if (collection.Count > 1)
                    {
                        throw new InvalidOperationException("Multiple Service Provider certificates were found, must only provide one.");
                    }
                    options.ServiceProvider.X509Certificate2 = collection[0];
                    if (options.ServiceProvider.X509Certificate2.PrivateKey == null)
                    {
                        throw new InvalidOperationException("The certificate for this service providerhas no private key.");
                    }
                    options.hasCertificate = true;
                }
            }
            var request = _httpContextAccessor.HttpContext.Request;
            options.AssertionURL_DEV = request.Scheme + "://" + request.Host.Value + options.CallbackPath;
            options.SignOutURL_DEV = request.Scheme + "://" + request.Host.Value + options.SignOutPath;

            if (options.Backchannel == null)
            {
                options.Backchannel = new HttpClient(options.BackchannelHttpHandler ?? new HttpClientHandler());
                options.Backchannel.DefaultRequestHeaders.UserAgent.ParseAdd("ASP.NET SamlCore handler");
                options.Backchannel.Timeout = options.BackchannelTimeout;
                options.Backchannel.MaxResponseContentBufferSize = 1024 * 1024 * 10; // 10 MB
            }

            if (string.IsNullOrEmpty(options.TokenValidationParameters.ValidAudience))
            {
                options.TokenValidationParameters.ValidAudience = options.ServiceProvider.EntityId;
            }

            if (options.ConfigurationManager == null)
            {
                if (options.Configuration != null)
                {
                    options.ConfigurationManager = new StaticConfigurationManager<Saml2Configuration>(options.Configuration);
                }
                else if (!string.IsNullOrEmpty(options.MetadataAddress))
                {
                    Uri uriResult;
                    bool result = Uri.TryCreate(options.MetadataAddress, UriKind.Absolute, out uriResult)
                        && (uriResult.Scheme == Uri.UriSchemeHttp || uriResult.Scheme == Uri.UriSchemeHttps);

                    if (result)
                    {
                        if (options.RequireHttpsMetadata && !options.MetadataAddress.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                        {
                            throw new InvalidOperationException("The MetadataAddress must use HTTPS unless disabled for development by setting RequireHttpsMetadata=false.");
                        }
                        options.ConfigurationManager = new ConfigurationManager<Saml2Configuration>(options.MetadataAddress, new Saml2ConfigurationRetriever(),
                           new HttpDocumentRetriever(options.Backchannel) { RequireHttps = options.RequireHttpsMetadata });
                    }
                    else
                    {
                        _idoc.GetDocumentAsync(options.MetadataAddress, default(CancellationToken));
                        options.ConfigurationManager = new ConfigurationManager<Saml2Configuration>(options.MetadataAddress, new Saml2ConfigurationRetriever(), _idoc);
                    }
                }
            }

            //delete the metadata.xml if exists
            string[] xmlList = Directory.GetFiles(options.DefaultMetadataFolderLocation, "*.xml");
            foreach (string f in xmlList)
            {
                if (f == options.DefaultMetadataFolderLocation + "\\" + options.DefaultMetadataFileName + ".xml")
                {
                    File.Delete(f);
                }
            }

            //overwrite or create metadata.xml if set to true
            if (options.CreateMetadataFile)
            {
                IndexedEndpointType[] AssertionConsumerService = new IndexedEndpointType[3];

                if (!string.IsNullOrEmpty(options.AssertionURL_PRD))
                {
                    AssertionConsumerService[0] = new IndexedEndpointType
                    {
                        Location = options.AssertionURL_PRD,
                        Binding = options.AssertionConsumerServiceProtocolBinding, //must only allow POST
                        index = 0,
                        isDefault = true,
                        isDefaultSpecified = true
                    };
                }
                if (!string.IsNullOrEmpty(options.AssertionURL_STG))
                {
                    AssertionConsumerService[1] = new IndexedEndpointType
                    {
                        Location = options.AssertionURL_STG,
                        Binding = options.AssertionConsumerServiceProtocolBinding, //must only allow POST
                        index = 1,
                        isDefault = false,
                        isDefaultSpecified = true
                    };
                }
                if (!string.IsNullOrEmpty(options.AssertionURL_DEV))
                {
                    AssertionConsumerService[2] = new IndexedEndpointType
                    {
                        Location = options.AssertionURL_DEV,
                        Binding = options.AssertionConsumerServiceProtocolBinding, //must only allow POST
                        index = 2,
                        isDefault = false,
                        isDefaultSpecified = true
                    };
                }


                //EndpointType[] SingleLogoutService = new EndpointType[3];
                //if (!string.IsNullOrEmpty(options.AssertionURL_PRD))
                //{
                //    SingleLogoutService[0] = new EndpointType
                //    {
                //        Location = options.SignOutURL_PRD,
                //        Binding = options.SingleLogoutServiceProtocolBinding //must only allow Redirect                        
                //    };
                //}
                //if (!string.IsNullOrEmpty(options.AssertionURL_STG))
                //{
                //    SingleLogoutService[1] = new EndpointType
                //    {
                //        Location = options.SignOutURL_STG,
                //        Binding = options.SingleLogoutServiceProtocolBinding //must only allow Redirect
                //    };
                //}
                //if (!string.IsNullOrEmpty(options.AssertionURL_DEV))
                //{
                //    SingleLogoutService[2] = new EndpointType
                //    {
                //        Location = options.SignOutURL_DEV,
                //        Binding = options.SingleLogoutServiceProtocolBinding //must only allow Redirect
                //    };
                //}

                Metadata.KeyDescriptorType[] KeyDescriptor = null;
                if (options.hasCertificate)
                {
                    KeyDescriptor = new Metadata.KeyDescriptorType[]
                             {
                                new Metadata.KeyDescriptorType()
                                {
                                    useSpecified= true,
                                    use = KeyTypes.signing,
                                    KeyInfo = new Metadata.KeyInfoType()
                                    {
                                        ItemsElementName = new []{ Metadata.ItemsChoiceType2.X509Data},
                                        Items = new Metadata.X509DataType[]
                                        {
                                            new Metadata.X509DataType()
                                            {
                                                Items = new object[]{options.ServiceProvider.X509Certificate2.GetRawCertData() },
                                                ItemsElementName = new [] { Metadata.ItemsChoiceType.X509Certificate }
                                            }
                                        }
                                    }
                                 },
                                new Metadata.KeyDescriptorType()
                                {
                                    useSpecified= true,
                                    use = KeyTypes.encryption,
                                    KeyInfo = new Metadata.KeyInfoType()
                                    {
                                        ItemsElementName = new []{ Metadata.ItemsChoiceType2.X509Data},
                                        Items = new Metadata.X509DataType[]
                                        {
                                            new Metadata.X509DataType()
                                            {
                                                Items = new object[]{ options.ServiceProvider.X509Certificate2.GetRawCertData() },
                                                ItemsElementName = new [] { Metadata.ItemsChoiceType.X509Certificate }
                                            }
                                        }
                                    }
                                 }
                             };
                }
                var entityDescriptor = new EntityDescriptorType()
                {
                    entityID = options.ServiceProvider.EntityId,
                    Items = new object[]
                {
                        new SPSSODescriptorType()
                        {
                            NameIDFormat = new [] {Saml2Constants.NameIDFormats.Email},
                            protocolSupportEnumeration = new []{Saml2Constants.Namespaces.Protocol },
                            AuthnRequestsSignedSpecified = true,
                            AuthnRequestsSigned = options.hasCertificate,
                            //(string.IsNullOrEmpty(options.ServiceProvider.SigningCertificateX509TypeValue)? false:true),
                            WantAssertionsSignedSpecified= true,
                            WantAssertionsSigned=true,
                            KeyDescriptor= KeyDescriptor,
                            //SingleLogoutService= SingleLogoutService,
                            SingleLogoutService = new EndpointType[]{
                                new EndpointType
                                {
                                    Location = options.SignOutURL_DEV,
                                    Binding = options.SingleLogoutServiceProtocolBinding //must only allow Post back to sp
                                }
                            },
                            AssertionConsumerService = AssertionConsumerService,
                            AttributeConsumingService =  new AttributeConsumingServiceType[]
                            {
                                new AttributeConsumingServiceType
                                {
                                    ServiceName =  new localizedNameType[]
                                    {
                                        new localizedNameType()
                                        {
                                            Value = options.ServiceProvider.ServiceName,
                                            lang = options.ServiceProvider.Language
                                        }
                                    },
                                    ServiceDescription = new localizedNameType[]
                                    {
                                        new localizedNameType()
                                        {
                                            Value= options.ServiceProvider.ServiceDescription,
                                            lang = options.ServiceProvider.Language
                                        }
                                    },
                                    index=0,
                                    isDefault =true,
                                    isDefaultSpecified = true,
                                    RequestedAttribute = new RequestedAttributeType[] //this doesnt work with ADFS
                                    {
                                        new RequestedAttributeType
                                        {
                                            isRequired = true,
                                            isRequiredSpecified = true,
                                            NameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                                            Name= "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
                                            FriendlyName = "Name"
                                        },
                                        new RequestedAttributeType
                                        {
                                            isRequired = true,
                                            isRequiredSpecified = true,
                                            NameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                                            Name = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
                                            FriendlyName = "E-Mail-Adresses"
                                        },
                                        new RequestedAttributeType
                                        {
                                            isRequired = true,
                                            isRequiredSpecified = true,
                                            NameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                                            Name= "nameid:persistent",
                                            FriendlyName = "mail"
                                        }
                                    }
                                }
                            },
                           Organization = new OrganizationType()
                                {
                                 OrganizationDisplayName = new localizedNameType[]{
                                     new localizedNameType
                                     {
                                         lang = options.ServiceProvider.Language,
                                         Value = options.ServiceProvider.OrganizationDisplayName
                                     },
                                 },
                                 OrganizationName = new localizedNameType[]{
                                     new localizedNameType
                                     {
                                         lang = options.ServiceProvider.Language,
                                         Value = options.ServiceProvider.OrganizationName
                                     },
                                 },
                                 OrganizationURL = new localizedURIType[]{
                                     new localizedURIType
                                     {
                                         lang = options.ServiceProvider.Language,
                                         Value = options.ServiceProvider.OrganizationURL
                                     },
                                 },
                            },
                       },
                },
                    ContactPerson = new ContactType[]
                {
                        new ContactType()
                        {
                            Company = options.ServiceProvider.ContactPerson.Company,
                            GivenName = options.ServiceProvider.ContactPerson.GivenName,
                            EmailAddress = options.ServiceProvider.ContactPerson.EmailAddress,
                            contactType = options.ServiceProvider.ContactPerson.contactType,
                            TelephoneNumber = options.ServiceProvider.ContactPerson.TelephoneNumber
                        }
                }
                };

                //generate the sp metadata xml file
                string xmlTemplate = string.Empty;
                XmlSerializer xmlSerializer = new XmlSerializer(typeof(EntityDescriptorType));
                using (MemoryStream memStm = new MemoryStream())
                {
                    xmlSerializer.Serialize(memStm, entityDescriptor);
                    memStm.Position = 0;
                    xmlTemplate = new StreamReader(memStm).ReadToEnd();
                }

                //create xml document from string
                XmlDocument xmlDoc = new XmlDocument();
                xmlDoc.LoadXml(xmlTemplate);
                xmlDoc.PreserveWhitespace = true;
                xmlDoc.Save(options.DefaultMetadataFolderLocation + "\\" + options.DefaultMetadataFileName + ".xml");
            }
        }
    }
}
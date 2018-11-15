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

using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Xml;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using static Microsoft.IdentityModel.Logging.LogHelper;
using static SamlCore.AspNetCore.Authentication.Saml2.Saml2Constants;

namespace SamlCore.AspNetCore.Authentication.Saml2
{
    /// <summary>
    /// 
    /// </summary>
    public class Saml2MetadataSerializer
    {
        /// <summary>
        /// The dsig serializer
        /// </summary>
        private DSigSerializer _dsigSerializer = DSigSerializer.Default;
        /// <summary>
        /// The preferred prefix
        /// </summary>
        private string _preferredPrefix = Saml2Constants.Prefixes.Fed;
        /// <summary>
        /// Metadata serializer for WsFed.
        /// </summary>
        public Saml2MetadataSerializer() { }
        /// <summary>
        /// Gets or sets the prefix to use when writing xml.
        /// </summary>
        /// <value>
        /// The preferred prefix.
        /// </value>
        /// <exception cref="ArgumentNullException">value</exception>
        public string PreferredPrefix
        {
            get => _preferredPrefix;
            set => _preferredPrefix = string.IsNullOrEmpty(value) ? throw LogExceptionMessage(new ArgumentNullException(nameof(value))) : value;
        }

        #region Read Metadata

        /// <summary>
        /// Read metadata and create the corresponding <see cref="Saml2Configuration" />.
        /// </summary>
        /// <param name="reader"><see cref="XmlReader" /> used to read metadata</param>
        /// <returns>
        ///   <see cref="Saml2Configuration" />
        /// </returns>
        /// <exception cref="XmlReadException">if error occurs when reading metadata</exception>
        public Saml2Configuration ReadMetadata(XmlReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, Elements.EntityDescriptor, Namespaces.MetadataNamespace);

            var envelopeReader = new EnvelopedSignatureReader(reader);

            try
            {
                var configuration = ReadEntityDescriptor(envelopeReader);
                configuration.Signature = envelopeReader.Signature;
                return configuration;
            }
            catch (Exception ex)
            {
                if (ex is XmlReadException)
                    throw;

                throw XmlUtil.LogReadException(LogMessages.IDX22800, ex, Elements.EntityDescriptor, ex);
            }
        }

        /// <summary>
        /// Read EntityDescriptor element in xml.
        /// </summary>
        /// <param name="reader"><see cref="XmlReader" /> used to read entity descriptor</param>
        /// <returns>
        ///   <see cref="Saml2Configuration" />
        /// </returns>
        /// <exception cref="XmlReadException">if error occurs when reading entity descriptor</exception>
        protected virtual Saml2Configuration ReadEntityDescriptor(XmlReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, Elements.EntityDescriptor, Namespaces.MetadataNamespace);

            var configuration = new Saml2Configuration();

            // get entityID for issuer
            var issuer = reader.GetAttribute(Attributes.EntityId);
            if (string.IsNullOrEmpty(issuer))
                throw XmlUtil.LogReadException(LogMessages.IDX22801);
            configuration.Issuer = issuer;

            bool isEmptyElement = reader.IsEmptyElement;

            // <EntityDescriptor>
            reader.ReadStartElement();

            while (reader.IsStartElement())
            {
                if (IsIDPSSODescriptor(reader))
                {
                    var endpoints = new Saml2Endpoints();
                    var roleDescriptor = new Saml2SecurityTokenServiceTypeRoleDescriptor();
                    reader.ReadStartElement();

                    while (reader.IsStartElement())
                    {
                        if (reader.IsStartElement(Elements.KeyDescriptor, Namespaces.MetadataNamespace) && reader.GetAttribute(Attributes.Use) == Saml2Constants.KeyUse.Signing)
                        {
                            roleDescriptor.KeyInfos.Add(ReadKeyDescriptorForSigning(reader));
                        }
                        else if (reader.IsStartElement(Elements.PassiveRequestorEndpoint, Namespaces.FedNamespace))
                        {
                            roleDescriptor.TokenEndpoint = ReadPassiveRequestorEndpoint(reader);
                        }
                        else if (reader.IsStartElement(Elements.SingleLogoutService, Namespaces.MetadataNamespace))
                        {
                            var location = new LocationWithBinding()
                            {
                                Location = reader.GetAttribute(Attributes.Location),
                                Binding = reader.GetAttribute(Attributes.Binding)
                            };
                            endpoints.SingleLogoutServices.Add(location);
                            reader.ReadOuterXml();
                        }
                        // <NameIDFormat >
                        else if (reader.IsStartElement(Elements.NameIDFormat, Namespaces.MetadataNamespace))
                        {
                            string nameID = reader.ReadElementContentAsString();
                            endpoints.NameIDFormats.Add(nameID);
                        }
                        // <SingleSignOnService>
                        else if (reader.IsStartElement(Elements.SingleSignOnService, Namespaces.MetadataNamespace))
                        {
                            var location = new LocationWithBinding()
                            {
                                Location = reader.GetAttribute(Attributes.Location),
                                Binding = reader.GetAttribute(Attributes.Binding)
                            };
                            endpoints.SingleSignOnServices.Add(location);
                            reader.ReadOuterXml();
                        }
                        else
                        {
                            reader.ReadOuterXml();
                        }
                    }

                    foreach (var keyInfo in roleDescriptor.KeyInfos)
                    {
                        configuration.KeyInfos.Add(keyInfo);
                        if (keyInfo.X509Data != null)
                        {
                            foreach (var data in keyInfo.X509Data)
                            {
                                foreach (var certificate in data.Certificates)
                                {
                                    var cert = new X509Certificate2(Convert.FromBase64String(certificate));
                                    configuration.SigningKeys.Add(new X509SecurityKey(cert));
                                    configuration.X509Certificate2 = new X509Certificate2(cert);
                                }
                            }
                        }
                    }
                    configuration.TokenEndpoint = roleDescriptor.TokenEndpoint;
                    configuration.SingleSignOnServices = endpoints.SingleSignOnServices;
                    configuration.SingleLogoutServices = endpoints.SingleLogoutServices;
                    configuration.NameIdFormat = endpoints.NameIDFormats;
                }
                else
                {
                    reader.ReadOuterXml();
                }
            }
            // </EntityDescriptor>
            if (!isEmptyElement)
                reader.ReadEndElement();
            return configuration;
        }

        /// <summary>
        /// Read KeyDescriptor element in xml.
        /// </summary>
        /// <param name="reader"><see cref="XmlReader" /> used to read key descriptor</param>
        /// <returns>
        ///   <see cref="KeyInfo" />
        /// </returns>
        /// <exception cref="XmlReadException">if error occurs when reading key descriptor</exception>
        protected virtual KeyInfo ReadKeyDescriptorForSigning(XmlReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, Elements.KeyDescriptor, Namespaces.MetadataNamespace);

            var use = reader.GetAttribute(Attributes.Use);
            if (string.IsNullOrEmpty(use))
                LogHelper.LogWarning(LogMessages.IDX22808);
            // <KeyDescriptor>  
            reader.ReadStartElement();
            reader.MoveToContent();

            if (reader.IsStartElement(XmlSignatureConstants.Elements.KeyInfo, XmlSignatureConstants.Namespace) && use == Saml2Constants.KeyUse.Signing)
            {
                var keyInfo = _dsigSerializer.ReadKeyInfo(reader);
                // </KeyDescriptor>
                reader.ReadEndElement();
                return keyInfo;
            }
            else
            {
                throw XmlUtil.LogReadException(LogMessages.IDX22802, reader.LocalName, reader.NamespaceURI, XmlSignatureConstants.Elements.KeyInfo, XmlSignatureConstants.Namespace);
            }
        }

        protected virtual Saml2SecurityTokenServiceTypeRoleDescriptor ReadSecurityTokenServiceTypeRoleDescriptor(XmlReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, Elements.IdpssoDescriptor, Namespaces.MetadataNamespace);

            //if (!IsSecurityTokenServiceTypeRoleDescriptor(reader))
            //    throw XmlUtil.LogReadException(LogMessages.IDX22804);

            var roleDescriptor = new Saml2SecurityTokenServiceTypeRoleDescriptor();

            // <IdpssoDescriptor>
            bool isEmptyElement = reader.IsEmptyElement;

            reader.ReadStartElement();

            while (reader.IsStartElement())
            {
                if (reader.IsStartElement(Elements.KeyDescriptor, Namespaces.MetadataNamespace))
                {
                    roleDescriptor.KeyInfos.Add(ReadKeyDescriptorForSigning(reader));
                }
                else if (reader.IsStartElement(Elements.PassiveRequestorEndpoint, Namespaces.FedNamespace))
                {
                    roleDescriptor.TokenEndpoint = ReadPassiveRequestorEndpoint(reader);
                }
                else
                {
                    reader.ReadOuterXml();
                }
            }
            // </ IdpssoDescriptor >
            if (!isEmptyElement)
                reader.ReadEndElement();

            if (roleDescriptor.KeyInfos.Count == 0)
                LogHelper.LogWarning(LogMessages.IDX22806);

            if (string.IsNullOrEmpty(roleDescriptor.TokenEndpoint))
                LogHelper.LogWarning(LogMessages.IDX22807);
            return roleDescriptor;
        }

        /// <summary>
        /// Reads the endpoints.
        /// </summary>
        /// <param name="reader">The reader.</param>
        /// <returns></returns>
        protected virtual Saml2Endpoints ReadEndpoints(XmlReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, Elements.IdpssoDescriptor, Namespaces.MetadataNamespace);

            if (reader.IsEmptyElement)
                throw XmlUtil.LogReadException(LogMessages.IDX22812, Elements.SingleSignOnService);

            var endpoints = new Saml2Endpoints();

            // <IDPSSO Descriptor>
            bool isEmptyElement = reader.IsEmptyElement;

            reader.ReadStartElement();
            while (reader.IsStartElement())
            {
                // <SingleLogoutService >
                if (reader.IsStartElement(Elements.SingleLogoutService, Namespaces.MetadataNamespace))
                {
                    var location = new LocationWithBinding()
                    {
                        Location = reader.GetAttribute(Attributes.Location),
                        Binding = reader.GetAttribute(Attributes.Binding)
                    };
                    endpoints.SingleLogoutServices.Add(location);
                    reader.ReadOuterXml();
                }
                // <NameIDFormat >
                else if (reader.IsStartElement(Elements.NameIDFormat, Namespaces.MetadataNamespace))
                {
                    string nameID = reader.ReadElementContentAsString();
                    endpoints.NameIDFormats.Add(nameID);
                    //reader.ReadOuterXml();
                }
                // <SingleSignOnService>
                else if (reader.IsStartElement(Elements.SingleSignOnService, Namespaces.MetadataNamespace))
                {
                    var location = new LocationWithBinding()
                    {
                        Location = reader.GetAttribute(Attributes.Location),
                        Binding = reader.GetAttribute(Attributes.Binding)
                    };
                    endpoints.SingleSignOnServices.Add(location);
                    reader.ReadOuterXml();
                }
                else
                {
                    reader.ReadOuterXml();
                }
            }
            //</ IDPSSO Descriptor >
            if (!isEmptyElement)
                reader.ReadEndElement();
            return endpoints;
        }

        /// <summary>
        /// Reads the single logout endpoints.
        /// </summary>
        /// <param name="reader">The reader.</param>
        /// <returns></returns>
        protected virtual List<LocationWithBinding> ReadSingleLogoutEndpoints(XmlReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, Elements.IdpssoDescriptor, Namespaces.MetadataNamespace);

            if (reader.IsEmptyElement)
                throw XmlUtil.LogReadException(LogMessages.IDX22812, Elements.SingleLogoutService);
            var singleLogout = new List<LocationWithBinding>();

            // <IDPSSO Descriptor>
            bool isEmptyElement = reader.IsEmptyElement;

            reader.ReadStartElement();
            while (reader.IsStartElement())
            {
                // <SingleLogoutService>
                if (reader.IsStartElement(Elements.SingleLogoutService, Namespaces.MetadataNamespace))
                {
                    var location = new LocationWithBinding()
                    {
                        Location = reader.GetAttribute(Attributes.Location),
                        Binding = reader.GetAttribute(Attributes.Binding)
                    };
                    singleLogout.Add(location);
                    reader.ReadOuterXml();
                }
                // </ SingleLogoutService >
                else
                {
                    reader.ReadOuterXml();
                }
            }
            // </IDPSSO Descriptor>
            if (!isEmptyElement)
                reader.ReadEndElement();

            if (singleLogout.Count == 0)
                throw XmlUtil.LogReadException(LogMessages.IDX22803);

            return singleLogout;
        }

        /// <summary>
        /// Read fed:PassiveRequestorEndpoint element in xml.
        /// </summary>
        /// <param name="reader"><see cref="XmlReader" /> used to read PassiveRequestorEndpoint</param>
        /// <returns>
        /// token endpoint string
        /// </returns>
        /// <exception cref="XmlReadException">if error occurs when reading PassiveRequestorEndpoint</exception>
        protected virtual string ReadPassiveRequestorEndpoint(XmlReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, Elements.PassiveRequestorEndpoint, Namespaces.FedNamespace);

            // <PassiveRequestorEndpoint>
            if (reader.IsEmptyElement)
                throw XmlUtil.LogReadException(LogMessages.IDX22812, Elements.PassiveRequestorEndpoint);

            reader.ReadStartElement();
            reader.MoveToContent();

            // <EndpointReference>
            XmlUtil.CheckReaderOnEntry(reader, Elements.EndpointReference, Namespaces.AddressNamespace);
            if (reader.IsEmptyElement)
                throw XmlUtil.LogReadException(LogMessages.IDX22812, Elements.EndpointReference);

            reader.ReadStartElement(Elements.EndpointReference, Namespaces.AddressNamespace);
            reader.MoveToContent();

            // </Address>
            if (reader.IsEmptyElement)
                throw XmlUtil.LogReadException(LogMessages.IDX22803);

            XmlUtil.CheckReaderOnEntry(reader, Elements.Address, Namespaces.AddressNamespace);
            if (reader.IsEmptyElement)
                throw XmlUtil.LogReadException(LogMessages.IDX22812, Elements.Address);

            reader.ReadStartElement(Elements.Address, Namespaces.AddressNamespace);
            reader.MoveToContent();

            var tokenEndpoint = Trim(reader.ReadContentAsString());

            if (string.IsNullOrEmpty(tokenEndpoint))
                throw XmlUtil.LogReadException(LogMessages.IDX22803);

            // </Address>
            reader.MoveToContent();
            reader.ReadEndElement();

            // </EndpointReference>
            reader.MoveToContent();
            reader.ReadEndElement();

            // </PassiveRequestorEndpoint>
            reader.MoveToContent();
            reader.ReadEndElement();

            return tokenEndpoint;
        }
        /// <summary>
        /// Determines whether [is idpsso descriptor] [the specified reader].
        /// </summary>
        /// <param name="reader">The reader.</param>
        /// <returns>
        ///   <c>true</c> if [is idpsso descriptor] [the specified reader]; otherwise, <c>false</c>.
        /// </returns>
        private bool IsIDPSSODescriptor(XmlReader reader)
        {
            if (reader == null || !reader.IsStartElement(Elements.IdpssoDescriptor, Namespaces.MetadataNamespace))
                return false;

            return true;
        }

        /// <summary>
        /// Determines whether [is security token service type role descriptor] [the specified reader].
        /// </summary>
        /// <param name="reader">The reader.</param>
        /// <returns>
        ///   <c>true</c> if [is security token service type role descriptor] [the specified reader]; otherwise, <c>false</c>.
        /// </returns>
        private bool IsSecurityTokenServiceTypeRoleDescriptor(XmlReader reader)
        {
            if (reader == null || !reader.IsStartElement(Elements.RoleDescriptor, Namespaces.MetadataNamespace))
                return false;

            var type = reader.GetAttribute(Attributes.Type, XmlSignatureConstants.XmlSchemaNamespace);
            var typeQualifiedName = new XmlQualifiedName();

            if (!string.IsNullOrEmpty(type))
                typeQualifiedName = XmlUtil.ResolveQName(reader, type);

            if (!XmlUtil.EqualsQName(typeQualifiedName, Types.SecurityTokenServiceType, Namespaces.FedNamespace))
                return false;
            return true;
        }

        /// <summary>
        /// Trims the specified string to trim.
        /// </summary>
        /// <param name="stringToTrim">The string to trim.</param>
        /// <returns></returns>
        internal static string Trim(string stringToTrim)
        {
            if (string.IsNullOrEmpty(stringToTrim))
                return stringToTrim;

            char[] charsToTrim = { ' ', '\n' };
            return stringToTrim.Trim(charsToTrim);
        }
        #endregion
    }
}

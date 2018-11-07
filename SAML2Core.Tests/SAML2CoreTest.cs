using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace SamlCore.AspNetCore.Authentication.Saml2.Tests
{
    /// <summary>
    /// 
    /// </summary>
    public class SAML2CoreTest
    {
        /// <summary>
        /// Verifies the scheme defaults.
        /// </summary>
        /// <returns></returns>
        [Fact]
        public async Task VerifySchemeDefaults()
        {
            var services = new ServiceCollection();
            services.AddAuthentication().AddSamlCore();
            var sp = services.BuildServiceProvider();
            var schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
            var scheme = await schemeProvider.GetSchemeAsync(Saml2Defaults.AuthenticationScheme);
            Assert.NotNull(scheme);
            Assert.Equal("Saml2Handler", scheme.HandlerType.Name);
            Assert.Equal(Saml2Defaults.AuthenticationScheme, scheme.DisplayName);
        }

        /// <summary>
        /// Missings the configuration throws.
        /// </summary>
        /// <returns></returns>
        [Fact]
        public async Task MissingConfigurationThrows()
        {
            var builder = new WebHostBuilder()
                .Configure(ConfigureApp)
                .ConfigureServices(services =>
                {
                    services.AddAuthentication(sharedOptions =>
                    {
                        sharedOptions.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                        sharedOptions.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                        sharedOptions.DefaultChallengeScheme = Saml2Defaults.AuthenticationScheme;
                    })
                    .AddCookie()
                    .AddSamlCore();
                });
            var server = new TestServer(builder);
            var httpClient = server.CreateClient();

            // Verify if the request is redirected to STS with right parameters
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => httpClient.GetAsync("/"));
            Assert.Equal("Provide MetadataAddress, Configuration, or ConfigurationManager to Saml2Options", exception.Message);
        }

        /// <summary>
        /// Challenges the redirects.
        /// </summary>
        /// <returns></returns>
        [Fact]
        public async Task ChallengeRedirects()
        {
            var httpClient = CreateHttpClient();
            // Verify if the request is redirected to STS with right parameters
            var response = await httpClient.GetAsync("/");
            Assert.Equal("https://S-DEVDC12.otsdev.la.gov/adfs/ls/", response.Headers.Location.GetLeftPart(System.UriPartial.Path), true);
            var queryItems = QueryHelpers.ParseQuery(response.Headers.Location.Query);
            Assert.True(queryItems["SamlRequest"].Any());
            Assert.True(queryItems["RelayState"].Any());
        }

        /// <summary>
        /// Maps the will not affect redirect.
        /// </summary>
        /// <returns></returns>
        [Fact]
        public async Task MapWillNotAffectRedirect()
        {
            var httpClient = CreateHttpClient();
            // Verify if the request is redirected to STS with right parameters
            var response = await httpClient.GetAsync("/mapped-challenge");
            Assert.Equal("https://S-DEVDC12.otsdev.la.gov/adfs/ls/", response.Headers.Location.GetLeftPart(System.UriPartial.Path), true);
            var queryItems = QueryHelpers.ParseQuery(response.Headers.Location.Query);
            Assert.True(queryItems["SamlRequest"].Any());
            Assert.True(queryItems["RelayState"].Any());
        }

        /// <summary>
        /// Pres the mapped will affect redirect.
        /// </summary>
        /// <returns></returns>
        [Fact]
        public async Task PreMappedWillAffectRedirect()
        {
            var httpClient = CreateHttpClient();
            // Verify if the request is redirected to STS with right parameters
            var response = await httpClient.GetAsync("/premapped-challenge");
            Assert.Equal("https://S-DEVDC12.otsdev.la.gov/adfs/ls/", response.Headers.Location.GetLeftPart(System.UriPartial.Path), true);
            var queryItems = QueryHelpers.ParseQuery(response.Headers.Location.Query);
            Assert.True(queryItems["SamlRequest"].Any());
            Assert.True(queryItems["RelayState"].Any());
        }
        /// <summary>
        /// Creates the HTTP client.
        /// </summary>
        /// <returns></returns>
        private HttpClient CreateHttpClient()
        {
            var builder = new WebHostBuilder()
                .Configure(ConfigureApp)
                .ConfigureServices(services =>
                {
                    services.AddAuthentication(sharedOptions =>
                    {
                        sharedOptions.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                        sharedOptions.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                        sharedOptions.DefaultChallengeScheme = Saml2Defaults.AuthenticationScheme;
                    })
                    .AddCookie()
                    .AddSamlCore(options =>
                    {
                        options.ForceAuthn = false;
                        options.SignOutPath = "/signedout";
                        options.ServiceProvider.EntityId = "https://localhost:5002";
                        options.ServiceProvider.SigningCertificateX509TypeValue = "1E0000428DD2559EBA25D96B8600000000428D";                                                                                                                                                        //options.MetadataAddress = @"FederationMetadata.xml"; //idp metadata file instead of address
                        options.MetadataAddress = "https://fs.otsdev.la.gov/federationmetadata/2007-06/FederationMetadata.xml";
                        options.BackchannelHttpHandler = new Saml2CoreMetadataDocumentHandler();
                        options.UseTokenLifetime = false;
                        options.DefaultMetadataFolderLocation = ".";
                        options.CreateMetadataFile = false;
                    });
                });
            var server = new TestServer(builder);
            server.BaseAddress = new Uri("https://localhost:5002");
            return server.CreateClient();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <seealso cref="System.Net.Http.HttpMessageHandler" />
        private class Saml2CoreMetadataDocumentHandler : HttpMessageHandler
        {
            /// <summary>
            /// Send an HTTP request as an asynchronous operation.
            /// </summary>
            /// <param name="request">The HTTP request message to send.</param>
            /// <param name="cancellationToken">The cancellation token to cancel operation.</param>
            /// <returns>
            /// The task object representing the asynchronous operation.
            /// </returns>
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                var metadata = File.ReadAllText(@"federationmetadata.xml");
                var newResponse = new HttpResponseMessage() { Content = new StringContent(metadata, Encoding.UTF8, "text/xml") };
                return Task.FromResult<HttpResponseMessage>(newResponse);
            }
        }

        /// <summary>
        /// Configures the application.
        /// </summary>
        /// <param name="app">The application.</param>
        private void ConfigureApp(IApplicationBuilder app)
        {
            app.Map("/PreMapped-Challenge", mapped =>
            {
                mapped.UseAuthentication();
                mapped.Run(async context =>
                {
                    await context.ChallengeAsync(Saml2Defaults.AuthenticationScheme);
                });
            });

            app.UseAuthentication();

            app.Map("/Logout", subApp =>
            {
                subApp.Run(async context =>
                {
                    if (context.User.Identity.IsAuthenticated)
                    {
                        var authProperties = new AuthenticationProperties() { RedirectUri = context.Request.GetEncodedUrl() };
                        await context.SignOutAsync(Saml2Defaults.AuthenticationScheme, authProperties);
                        await context.Response.WriteAsync("Signing out...");
                    }
                    else
                    {
                        await context.Response.WriteAsync("SignedOut");
                    }
                });
            });

            app.Map("/AuthenticationFailed", subApp =>
            {
                subApp.Run(async context =>
                {
                    await context.Response.WriteAsync("AuthenticationFailed");
                });
            });

            app.Map("/signout-saml2", subApp =>
            {
                subApp.Run(async context =>
                {
                    await context.Response.WriteAsync("signout-wsfed");
                });
            });

            app.Map("/mapped-challenge", subApp =>
            {
                subApp.Run(async context =>
                {
                    await context.ChallengeAsync(Saml2Defaults.AuthenticationScheme);
                });
            });

            app.Run(async context =>
            {
                var result = context.AuthenticateAsync(Saml2Defaults.AuthenticationScheme);

                if (context.User == null || !context.User.Identity.IsAuthenticated)
                {
                    await context.ChallengeAsync(Saml2Defaults.AuthenticationScheme);
                    await context.Response.WriteAsync("UUnauthorized");
                }
                else
                {
                    var identity = context.User.Identities.Single();
                    if (identity.NameClaimType == "Name_Failed" && identity.RoleClaimType == "Role_Failed")
                    {
                        context.Response.StatusCode = 500;
                        await context.Response.WriteAsync("SignIn_Failed");
                    }
                    else if (!identity.HasClaim("Authenticated", "true") || !identity.HasClaim("ReturnEndpoint", "true") || !identity.HasClaim(identity.RoleClaimType, "Guest"))
                    {
                        await context.Response.WriteAsync("Provider not invoked");
                        return;
                    }
                    else
                    {
                        await context.Response.WriteAsync(Saml2Defaults.AuthenticationScheme);
                    }
                }
            });
        }
    }
}
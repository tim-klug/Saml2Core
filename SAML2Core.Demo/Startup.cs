using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SamlCore.AspNetCore.Authentication.Saml2.Metadata;

namespace Saml2Authentication
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddHttpContextAccessor(); //add for Saml2Core
            services.Configure<CookiePolicyOptions>(options =>
            {
                // This lambda determines whether user consent for non-essential cookies is needed for a given request.
                options.CheckConsentNeeded = context => true;
                options.MinimumSameSitePolicy = SameSiteMode.None;
            });


            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_1);

            services.AddAuthentication(sharedOptions =>
            {
                sharedOptions.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                sharedOptions.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })
          .AddSamlCore(options => //add for Saml2Core
          {
              //required
              options.SignOutPath = "/signedout"; //setting up the assertion consumer url on idp side              
              options.ServiceProvider.EntityId = Configuration["AppConfiguration:ServiceProvider:EntityId"]; // relying party identifier eg https://my.la.gov.local
              //options.MetadataAddress = @"FederationMetadata.xml"; //idp metadata file instead of a url address
              options.MetadataAddress = Configuration["AppConfiguration:IdentityProvider:MetadataAddress"]; //idp metadata url address  
                   
              //optional
              //options.ServiceProvider.CertificateIdentifierType = X509FindType.FindBySerialNumber; // the default is 'X509FindType.FindBySerialNumber'. Change value of 'options.ServiceProvider.SigningCertificateX509TypeValue' if this changes
              options.ServiceProvider.SigningCertificateX509TypeValue = Configuration["AppConfiguration:ServiceProvider:CertificateSerialNumber"]; //your certifcate serial number (default type which can be chnaged by ) that is in your certficate store
              options.CreateMetadataFile = true;
              options.ForceAuthn = true;
              options.ServiceProvider.ServiceName = "My Test Site";
              options.ServiceProvider.Language = "en-US";
              options.ServiceProvider.OrganizationDisplayName = "Louisiana State Government";
              options.ServiceProvider.OrganizationName = "Louisiana State Government";
              options.ServiceProvider.OrganizationURL = "https://my.test.site.gov";
              options.ServiceProvider.ContactPerson = new ContactType()
              {
                  Company = "Louisiana State Government - OTS",
                  GivenName = "Dina Heidar",
                  EmailAddress = new[] { "dina.heidar@la.gov" },
                  contactType = ContactTypeType.technical,
                  TelephoneNumber = new[] { "+1 234 5678" }
              };
              options.CreateMetadataFile = true; //if true, it'll create an SP metadata file which can be located at 'https://[your host]/metadata.xml'
              
              //optional customization (in case you need to add something to the returning calls/claims)
              //options.Events.OnRemoteFailure = context =>
              //{
              //    return Task.FromResult(0);
              //};              
              //options.Events.OnTicketReceived = context =>
              //{  //TODO: add custom claims here
              //    return Task.FromResult(0);
              //};               
          })
          .AddCookie();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseCookiePolicy();

            app.UseAuthentication(); //add for Saml2Core

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
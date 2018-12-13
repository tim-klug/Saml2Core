# Options

### 1. Required

| Name                      | Example value                                                                 | Datatype          |    Description    |
| -------------             |-------------                                                                  | -----             |    -----         |
| SignOutPath               | "/signedout"                                                                  | string            | The endpoint for the IDP to perform its signout action |
| ServiceProvider.EntityId  | "https://my.la.gov.local"                                                     | string            | The Relying Party Identifier
| MetadataAddress           | "https://dev.adfs.la.gov/federationmetadata/2007-06/FederationMetadata.xml"  | string            | The IDP FederationMetadata. This can be either a URL or a file at the root of your project e.g '@"FederationMetadata.xml"'



##### The following section is if your application (SP) has a certificate and is signing the Authn Request with it.

###### PRE-REQUISITE: Install your certificate in your server/local certificate store under the Trusted Root folder. [Click here](https://blogs.technet.microsoft.com/sbs/2008/05/08/installing-a-self-signed-certificate-as-a-trusted-root-ca-in-windows-vista)
| Name                                                  | Example value                                     | Datatype          |    Description    |
| -------------                                         |-------------                                      | -----             |    -----          |
| ServiceProvider.SigningCertificateX509TypeValue       | "1E0000428DD2559EBA25D96B8600000000428D"          | string            | The SP certificate serial number value       |


 
### 2. Optional

| Name                      | Example value                                                                 | Datatype          |    Description    |
| -------------             |-------------                                                                  | -----             |    -----         |
| WantAssertionsSigned | true | boolean | Require the IDP to sign assertions. The default is 'false' |
| RequireMessageSigned | false | boolean | Require the IDP to sign assertions. The default is 'false'. This must be set as well on IDP side. |  
| CreateMetadataFile              | true                                                                 | boolean           | Have the middleware create the metadata file for you. The default is false.|
| DefaultMetadataFileName  | "MyMetadataFilename"                                                  | string            | the default is "Metadata"
| DefaultMetadataFolderLocation           | "MyPath" | string            | the default is "wwwroot" so it can be accessible via "https://[host name]/MyMetadataFilename.xml".
| ForceAuthn| true| boolean| if you are requiring users to enter credentials into the IDP every time. Default is set to true
| ServiceProvider.ApplicationProductionURL |"https://my.la.gov" | string | this will create a production signin endpoint on the IDP side. This will be used when deployed to your production site
| ServiceProvider.ApplicationStageURL |"https://stage.my.la.gov" | string | this will create a stage signin endpoint on the IDP side. This will be used when deployed to your production site
| ServiceProvider.ServiceName |"My Test Site" | string | 
| ServiceProvider.Language | "en-US" | string |


##### The following section is if your application (SP) has a certificate and is signing the Authn Request with it.

The middleware searches by default by serial number in the Trusted Root folder. This can be changed by:

| Name                                                      | Example value                 | Datatype          |    Description    |
| -------------                                             |-------------                  | -----             |    -----          |
| ServiceProvider.CertificateStoreName                      | StoreName.Root                | enum              | Store name        |
| ServiceProvider.CertificateStoreLocation                  | StoreLocation.LocalMachine    | enum              | Store location    |
| ServiceProvider.CertificateStoreLocation.HashAlgorithm    | HashAlgorithmName.SHA256     | enum               |  Hash Algorithm Name |
| ServiceProvider.CertificateIdentifierType                 |X509FindType.FindBySerialNumber| enum | the default is 'X509FindType.FindBySerialNumber'.
   


# Usage

1. Modify `ConfigureServices()` in Startup.cs
```cs
services.AddAuthentication(sharedOptions =>
{
    sharedOptions.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    sharedOptions.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
})
.AddSamlCore(options =>
{   
    options.SignOutPath = "/signedout";
    options.ServiceProvider.EntityId = Configuration["AppConfiguration:ServiceProvider:EntityId"];

    // There are two ways to provide FederationMetadata
    // Option 1 - A FederationMetadata.xml already exists for your application
    // options.MetadataAddress = @"FederationMetadata.xml";

    // Option 2 - Have the middleware generate the FederationMetadata.xml file for you
    options.MetadataAddress = Configuration["AppConfiguration:IdentityProvider:MetadataAddress"];
   
    options.CreateMetadataFile = true; 
    options.ServiceProvider.SigningCertificateX509TypeValue = Configuration["AppConfiguration:ServiceProvider:CertificateSerialNumber"]; //your certifcate serial number (default type which can be chnaged by ) that is in your certficate store
    options.ForceAuthn = true;

    // Service Provider Properties (optional) - These set the appropriate tags in the metadata.xml file
    options.ServiceProvider.ApplicationProductionURL = "https://my.la.gov"; // this will create a production signin endpoint on the Idp side. This will be used when deployed to your production site
    options.ServiceProvider.ApplicationStageURL = "https://dev.my.la.gov"; //this will create a stage signin endpoint on the Idp side. This will be used when deployed to your stage site
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

    // Events - Modify events below if you want to log errors, add custom claims, etc.
    //options.Events.OnRemoteFailure = context =>
    //{
    //TODO: do whatever you want here if you need to re-direct to somewhere if there 
    // an error from provider
    //    context.Response.Redirect(new PathString("/Account/Login"));
          context.HandleResponse();
    //    return Task.FromResult(0);
    //};              
    //options.Events.OnTicketReceived = context =>
    //{  
    //TODO: add custom claims here
    //    var identity = (ClaimsIdentity)context.Principal.Identity;
    //    identity.RemoveClaim(identity.FindFirst(ClaimTypes.Name)); //remove the screen name to add full name
    //    identity.AddClaim(new Claim(ClaimTypes.Name, context.User["name"].ToString()));
    //    return Task.FromResult(0);
    //};               
})
.AddCookie();
```

2. Don't forget to add the following line in `Configure()`

```cs
app.UseAuthentication();
```
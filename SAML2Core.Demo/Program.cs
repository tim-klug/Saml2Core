using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace Saml2Authentication
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateWebHostBuilder(args).Run();
        }

        public static IWebHost CreateWebHostBuilder(string[] args) =>
            WebHost.CreateDefaultBuilder(args)
                .UseKestrel(options =>
                {
                    // listen for HTTP
                    //options.Listen(IPAddress.Parse("127.0.0.1"), 5007);
                    options.Listen(IPAddress.Parse("127.0.0.1"), 60548);

                    using (var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine))
                    {
                        store.Open(OpenFlags.ReadOnly);
                        var certificates = store.Certificates.OfType<X509Certificate2>().ToLi‌​st();
                        X509Certificate2 cert = certificates.Where(x => x.SerialNumber == "1E0000428DD2559EBA25D96B8600000000428D").SingleOrDefault();

                        // listen for HTTPS
                        //options.Listen(IPAddress.Parse("127.0.0.1"), 5008, listenOptions =>
                        options.Listen(IPAddress.Parse("127.0.0.1"), 44340, listenOptions =>
                        {
                            listenOptions.UseHttps(cert);
                        });
                    }
                })
            .UseStartup<Startup>()
            .Build();
    }
}

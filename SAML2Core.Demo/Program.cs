using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Serilog;
using System;
using System.IO;

namespace Saml2Authentication
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .AddJsonFile($"appsettings.{Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT")}.json", optional: true)
                .Build();

            Log.Logger = new LoggerConfiguration()
                .ReadFrom.Configuration(configuration)
                .CreateLogger();

            try
            {
                Log.Information("Starting BuildWebHost ...");

                BuildWebHost(args).Run();
            }
            catch (Exception ex)
            {
                Log.Fatal(ex, "Host terminated unexpectedly");
            }
            finally
            {
                Log.CloseAndFlush();
            }

        }

        public static IWebHost BuildWebHost(string[] args) =>
            WebHost.CreateDefaultBuilder(args)
                .UseStartup<Startup>()
                .UseSerilog()
                .Build();
    }
    //public class Program
    //{
    //    public static void Main(string[] args)
    //    {
    //        CreateWebHostBuilder(args).Run();
    //    }

    //    public static IWebHost CreateWebHostBuilder(string[] args) =>
    //        WebHost.CreateDefaultBuilder(args)
    //            .UseKestrel(options =>
    //            {
    //                // listen for HTTP
    //                //options.Listen(IPAddress.Parse("127.0.0.1"), 5007);
    //                options.Listen(IPAddress.Parse("127.0.0.1"), 60548);

    //                using (var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine))
    //                {
    //                    store.Open(OpenFlags.ReadOnly);
    //                    var certificates = store.Certificates.OfType<X509Certificate2>().ToLi‌​st();
    //                    X509Certificate2 cert = certificates.Where(x => x.SerialNumber == "1E0000428DD2559EBA25D96B8600000000428D").SingleOrDefault();

    //                    // listen for HTTPS
    //                    options.Listen(IPAddress.Parse("127.0.0.1"), 5008, listenOptions =>
    //                    //options.Listen(IPAddress.Parse("127.0.0.1"), 44340, listenOptions =>
    //                    {
    //                        listenOptions.UseHttps(cert);
    //                    });
    //                }
    //            })
    //        .UseStartup<Startup>()
    //        .Build();
    //}
}

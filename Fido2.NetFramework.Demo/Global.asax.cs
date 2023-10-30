using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Routing;
using System.Web.Security;
using System.Web.SessionState;
using System.Web.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Fido2.NetFramework.Demo.Code;
using Microsoft.Extensions.Configuration;
using Fido2NetLib;
using Microsoft.Extensions.Options;
using System.Configuration;
using System.ComponentModel;
using System.Data.Entity;

namespace Fido2.NetFramework.Demo
{
    public class Global : HttpApplication
    {
        void Application_Start(object sender, EventArgs e)
        {
            // Code that runs on application startup
            AreaRegistration.RegisterAllAreas();
            GlobalConfiguration.Configure(WebApiConfig.Register);
            RouteConfig.RegisterRoutes(RouteTable.Routes);

            CompositionRoot();
        }

        protected void Application_PostAuthorizeRequest()
        {
            if ( IsWebApiRequest() )
            {
                HttpContext.Current.SetSessionStateBehavior( SessionStateBehavior.Required );
            }
        }

        private bool IsWebApiRequest()
        {
            return HttpContext.Current.Request.AppRelativeCurrentExecutionFilePath.StartsWith( WebApiConfig.UrlPrefixRelative );
        }

        public static IServiceProvider ServiceLocator { get; set; }

        void CompositionRoot()
        {
            var hostBuilder = CreateHostBuilder();
            var host = hostBuilder.Build();


            Global.ServiceLocator = host.Services;

            Database.SetInitializer( new DropCreateDatabaseIfModelChanges<FidoDbContext>() );
        }

        IHostBuilder CreateHostBuilder()
        {
            return Host.CreateDefaultBuilder()
                .ConfigureServices( ( context, services ) => {
                    services
                       .AddScoped<IFido2>( s =>
                        {
                            var fido2Configuration = new Fido2Configuration();

                            fido2Configuration.ServerDomain            = System.Configuration.ConfigurationManager.AppSettings["serverDomain"];
                            fido2Configuration.ServerName              = "FIDO2 Test";
                            fido2Configuration.Origins = new HashSet<string>( new[] { System.Configuration.ConfigurationManager.AppSettings["origins"] } );
                            fido2Configuration.TimestampDriftTolerance = int.Parse ( System.Configuration.ConfigurationManager.AppSettings["timestampDriftTolerance"] );

                            var fido2 = new Fido2NetLib.Fido2( fido2Configuration );

                            return fido2;
                        } )
                        .AddScoped<FidoDbContext>( s =>
                        {
                            var cs = System.Configuration.ConfigurationManager.AppSettings["ConnectionStrings:FidoDbContext"];

                            return new FidoDbContext( cs );
                        } )
                        .AddScoped<DevelopmentCustomStore>( s =>
                        {
                            var ctx = s.GetService<FidoDbContext>();

                            return new DevelopmentCustomStore( ctx );
                        } );
                } );
        }
    }
}
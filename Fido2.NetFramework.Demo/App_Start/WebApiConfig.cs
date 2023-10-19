using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Formatting;
using System.Web.Http;

namespace Fido2.NetFramework.Demo
{
    public static class WebApiConfig
    {
        public static string UrlPrefix { get { return "api"; } }
        public static string UrlPrefixRelative { get { return "~/api"; } }

        public static void Register( HttpConfiguration config )
        {
            var jsonformatter = new JsonMediaTypeFormatter
            {
                SerializerSettings =
                {
                    NullValueHandling = NullValueHandling.Ignore
                }
            };

            config.Formatters.RemoveAt( 0 );
            config.Formatters.Insert( 0, jsonformatter );

            config.MapHttpAttributeRoutes();
            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: WebApiConfig.UrlPrefix + "/{controller}/{id}",
                defaults: new { id = RouteParameter.Optional }
            );
        }
    }
}

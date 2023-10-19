using Fido2.NetFramework.Demo.Code;
using Fido2.NetFramework.Demo.Models.Home;
using Fido2NetLib;
using Microsoft.Extensions.DependencyInjection;
using System.Linq;
using System.Web.Mvc;

namespace Fido2.NetFramework.Demo.Controllers.MVC
{
    public class HomeController : Controller
    {
        private DevelopmentCustomStore _demoStorage;

        public HomeController()
        {
            _demoStorage = Global.ServiceLocator.GetService<DevelopmentCustomStore>();
        }

        public ActionResult Index()
        {
            var model = new IndexModel();
            if ( this.User.Identity.IsAuthenticated )
            {
                var user = this._demoStorage.GetUser( this.User.Identity.Name );
                if ( user != null )
                {
                    model.StoredCredentialsCount = _demoStorage.GetCredentialsByUser( user ).Count();
                }
            }

            return View(model);
        }
    }
}

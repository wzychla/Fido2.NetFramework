using System.Security.Claims;
using Fido2NetLib;
using System.Linq.Expressions;
using System.Web.Mvc;
using Fido2.NetFramework.Demo.Code;
using System.Threading.Tasks;
using Fido2.NetFramework.Demo.Models.Account;
using System;
using System.Web.Security;
using Microsoft.Extensions.DependencyInjection;

namespace Fido2.NetFramework.Demo.Controllers.MVC
{
    public class AccountController : Controller
    {
        private DevelopmentCustomStore _demoStorage;

        public AccountController()
        {           
            _demoStorage = Global.ServiceLocator.GetService<DevelopmentCustomStore>(); 
        }

        [HttpGet]
        public ActionResult Logon()
        {
            var model = new LogonModel();
            return View( model );
        }

        [HttpPost]
        public async Task<ActionResult> Logon( LogonModel model )
        {
            try
            {
                if ( this.ModelState.IsValid )
                {
                    var username = model.UserName;
                    var password = model.Password;

                    if ( this._demoStorage.ValidateUser( username, password ) )
                    {

                        // create identity
                        var identity = new ClaimsIdentity(
                    new []
                    {
                        new Claim( ClaimTypes.NameIdentifier, Guid.NewGuid().ToString() ),
                        new Claim( ClaimTypes.Name, username )
                    }, "custom");
                        ClaimsPrincipal principal = new ClaimsPrincipal(identity);

                        FormsAuthentication.SetAuthCookie( username, false );

                        return Redirect( "/" );
                    }
                    else
                    {
                        this.ViewBag.Message = "Zła nazwa użytkownika lub hasło";
                        return View( model );
                    }
                }
                else
                {
                    this.ViewBag.Message = "Należy prawidłowo wypełnić formularz";
                    return View( model );
                }
            }
            catch ( Exception ex )
            {
                this.ViewBag.Message = ex.ToString();
                return View( model );
            }
        }

        [HttpGet]
        public ActionResult Create()
        {
            var model = new CreateModel();
            return View( model );
        }

        [HttpPost]
        public ActionResult Create(CreateModel model)
        {
            if ( this.ModelState.IsValid )
            {
                var user = this._demoStorage.GetUser( model.UserName );
                if ( user == null )
                {
                    this._demoStorage.AddUser( model.UserName, model.Password );
                    this.TempData.Add( "message", "Konto zostało utworzone" );
                    return Redirect( "/" );
                }
                else
                {
                    this.ViewBag.Message = "Użytkownik o takiej nazwie już istnieje";
                    return View( model );
                }
            }
            else
            {
                this.ViewBag.Message = "Należy prawidłowo wypełnić formularz";
                return View( model );
            }
        }

        public async Task<ActionResult> LogOff()
        {
            FormsAuthentication.SignOut();

            return Redirect( "/" );
        }
    }
}

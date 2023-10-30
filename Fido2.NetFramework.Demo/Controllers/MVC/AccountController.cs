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
                        this.ViewBag.Message = "Username or password incorrect";
                        return View( model );
                    }
                }
                else
                {
                    this.ViewBag.Message = "There were errors in the form";
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
                    this.TempData.Add( "message", "Account has been created" );
                    return Redirect( "/" );
                }
                else
                {
                    this.ViewBag.Message = "User already exists";
                    return View( model );
                }
            }
            else
            {
                this.ViewBag.Message = "There were errors in the form";
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

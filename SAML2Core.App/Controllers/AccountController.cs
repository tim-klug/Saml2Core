using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace SAML2Core.App.Controllers
{
    public class AccountController : Controller
    {
        private readonly IHttpContextAccessor _context;

        public AccountController(IHttpContextAccessor context)
        {
            _context = context;
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult ExternalLogin(string provider, string returnUrl = null)
        {
            // Request a redirect to the external login provider.
            if (returnUrl == null || Url.IsLocalUrl(returnUrl))
            {
                // Request a redirect to the external login provider.
                var redirectUrl = Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl });
                var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
                properties.Items["LoginProviderKey"] = provider;
                return Challenge(properties, provider);
            }
            return RedirectToAction("Index", "Home");
        }

        [HttpGet]
        [AllowAnonymous]
        [Route("Account/ExternalLoginCallback")]
        public IActionResult ExternalLoginCallback(string returnUrl = null, string remoteError = null)
        {
            if (Url.IsLocalUrl(returnUrl)) //e.g. user returning to confirm email
            {
                return LocalRedirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
        }

        [HttpPost]
        public async Task Logout()
        {
            var result = await _context.HttpContext.AuthenticateAsync();
            var properties = result.Properties;
            var provider = properties.Items[".AuthScheme"];
            await _context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            await _context.HttpContext.SignOutAsync(provider, properties);
        }
    }
}
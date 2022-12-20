using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Xml;

namespace kbaidptest.Controllers
{
    [AllowAnonymous]
    [Route("Auth")]
    public class AuthController : Controller
    {
        const string relayStateReturnUrl = "ReturnUrl";
        private readonly IConfiguration _config;

        public AuthController(IConfiguration config)
        {           
            _config = config;
        }

        [Route("Login/{idp}")]
        public IActionResult Login(string idp, string? returnUrl)
        {
            var samlConfig = _config.GetSamlConfig(idp);
            var binding = new Saml2RedirectBinding();
            binding.SetRelayStateQuery(
                new Dictionary<string, string> { { relayStateReturnUrl, returnUrl ?? Url.Content("~/") } }
            );
            return binding.Bind(new Saml2AuthnRequest(samlConfig)).ToActionResult();
        }

        [HttpPost("Logout/{idp}")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(string idp)
        {
            if (User.Identity == null || !User.Identity.IsAuthenticated)
            {
                return Redirect(Url.Content("~/"));
            }
            var samlConfig = _config.GetSamlConfig(idp);
            var binding = new Saml2PostBinding();
            var saml2LogoutRequest = await new Saml2LogoutRequest(samlConfig, User).DeleteSession(HttpContext);
            return binding.Bind(saml2LogoutRequest).ToActionResult();
        }

        [Route("LoggedOut/{idp}")]
        public IActionResult LoggedOut(string idp)
        {
            var samlConfig = _config.GetSamlConfig(idp);
            var binding = new Saml2PostBinding();
            binding.Unbind(Request.ToGenericHttpRequest(), new Saml2LogoutResponse(samlConfig));

            return Redirect(Url.Content("~/"));
        }

        [Route("AssertionConsumerService/{idp}")]
        public async Task<IActionResult> AssertionConsumerService(string idp)
        {
            var samlConfig = _config.GetSamlConfig(idp);
            var binding = new Saml2PostBinding();
            var saml2AuthnResponse = new Saml2AuthnResponse(samlConfig);
            var request = Request.ToGenericHttpRequest();
            try
            {
                binding.Unbind(request, saml2AuthnResponse);
            }
            catch
            {
                var doc = GetSamlResponseFromHttpRequest(request);
                if (doc != null)
                {
                    return View(doc);
                }
            }
            await saml2AuthnResponse.CreateSession(HttpContext,
                claimsTransform: (claimsPrincipal) => ClaimsTransform.Transform(claimsPrincipal)
            );
            return Redirect("~/Claims");
        }

        private static XmlDocument? GetSamlResponseFromHttpRequest(ITfoxtec.Identity.Saml2.Http.HttpRequest request)
        {
            if (request.Form.AllKeys.Length == 0)
            {
                return null;
            }

            if (!request.Form.AllKeys.Where(k => k != null && k.Equals("SAMLResponse")).Any())
            {
                return null;
            }
            string? samlResponse = request.Form["SAMLResponse"];
            if (samlResponse == null)
            {
                return null;
            }
            using var ms = new MemoryStream(Convert.FromBase64String(samlResponse));
            var xmlDocument = new XmlDocument();
            xmlDocument.Load(ms);
            return xmlDocument;
        }
    }
}
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
        private readonly IConfiguration _config;
        private readonly IHttpClientFactory _httpClientFactory;

        public AuthController(IConfiguration config, IHttpClientFactory httpClientFactory)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
        }

        [Route("Login/{idp}")]
        public async Task<IActionResult> Login(string idp, string? returnUrl)
        {
            var samlConfig = await _config.GetSamlSignonConfig(
                _httpClientFactory,
                idp,
                returnUrl ?? Url.Content("~/")
            );

            return samlConfig.Bind(new Saml2AuthnRequest(samlConfig.Saml2Configuration));
        }

        [HttpPost("Logout/{idp}")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(string idp)
        {
            if (User.Identity == null || !User.Identity.IsAuthenticated)
            {
                return Redirect(Url.Content("~/"));
            }
            var samlConfig = await _config.GetSamlLogoutConfig(_httpClientFactory, idp);

            if (samlConfig == null)
            {
                return Redirect(Url.Content("~/"));
            }

            return samlConfig.Bind(new Saml2LogoutRequest(samlConfig.Saml2Configuration, User));
        }

        [Route("LoggedOut/{idp}")]
        public async Task<IActionResult> LoggedOut(string idp)
        {
            var samlConfig = await _config.GetSamlLogoutConfig(_httpClientFactory, idp);

            samlConfig?.Unbind(Request.ToGenericHttpRequest(), new Saml2LogoutResponse(samlConfig.Saml2Configuration));

            return Redirect(Url.Content("~/"));
        }

        [Route("AssertionConsumerService/{idp}")]
        public async Task<IActionResult> AssertionConsumerService(string idp)
        {
            var samlConfig = _config.GetSamlAssertionConsumerConfig(idp);

            if (samlConfig == null)
            {
                return Redirect(Url.Content("~/"));
            }

            var saml2AuthnResponse = new Saml2AuthnResponse(samlConfig.Saml2Configuration);
            var request = Request.ToGenericHttpRequest();
            try
            {
                samlConfig.Unbind(request, saml2AuthnResponse);
            }
            catch
            {
                var doc = GetSamlResponseFromHttpRequest(request);
                if (doc != null)
                {
                    return View(doc);
                }
                return Redirect(Url.Content("~/Error"));
            }
            await saml2AuthnResponse.CreateSession(HttpContext,
                claimsTransform: (c) => ClaimsTransform.Transform(c)
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
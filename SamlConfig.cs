using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using ITfoxtec.Identity.Saml2;
using Microsoft.AspNetCore.Mvc;
using ITfoxtec.Identity.Saml2.MvcCore;

namespace kbaidptest
{
    public class SamlConfig
    {
        public SamlConfig(Saml2Configuration saml2Configuration, Saml2Binding binding)
        {
            Saml2Configuration = saml2Configuration;
            Binding = binding;
        }

        public Saml2Configuration Saml2Configuration { get; private set; }
        public Saml2Binding Binding { get; private set; }

        public IActionResult Bind(Saml2Request request)
        {
            if (Binding is Saml2PostBinding postBinding)
            {
                return postBinding.Bind(request).ToActionResult();
            }

            if (Binding is Saml2RedirectBinding redirectBinding)
            {
                return redirectBinding.Bind(request).ToActionResult();
            }

            throw new NotImplementedException();
        }

        public Saml2Response Unbind(ITfoxtec.Identity.Saml2.Http.HttpRequest request, Saml2Response response)
        {
            if (Binding is Saml2PostBinding postBinding)
            {
                return postBinding.Unbind(request, response);
            }

            if (Binding is Saml2RedirectBinding redirectBinding)
            {
                return redirectBinding.Unbind(request, response);
            }

            throw new NotImplementedException();
        }
    }

    public static class SamlConfigExtensions
    {
        private static readonly Uri PostBinding = new("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
        private static readonly Uri RedirectBinding = new("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");

        private static async Task<EntityDescriptor> GetEntiyDescriptor(IConfiguration config, IHttpClientFactory httpClientFactory, string idp)
        {
            ArgumentNullException.ThrowIfNull(config);
            ArgumentNullException.ThrowIfNull(httpClientFactory);
            ArgumentException.ThrowIfNullOrEmpty(idp);

            var idpMetadataUri = GetMetadataUri(config, idp);
            EntityDescriptor entityDescriptor = new();
            await entityDescriptor.ReadIdPSsoDescriptorFromUrlAsync(httpClientFactory, idpMetadataUri);
            if (entityDescriptor.IdPSsoDescriptor == null)
            {
                throw new Exception("IdPSsoDescriptor not loaded from metadata.");
            }
            return entityDescriptor;
        }

        private static Saml2Binding GetSaml2Binding(Uri bindingUri)
        {
            if (bindingUri == PostBinding) return new Saml2PostBinding();
            if (bindingUri == RedirectBinding) return new Saml2RedirectBinding();

            throw new InvalidOperationException("Unknown SAML binding");
        }

        private static Saml2Configuration GetSaml2Configuration(IConfiguration config, string idp)
        {
            ArgumentNullException.ThrowIfNull(config);
            ArgumentException.ThrowIfNullOrEmpty(idp);

            var saml2Config = new Saml2Configuration();
            config.Bind($"Saml2:{idp}", saml2Config);
            return saml2Config;
        }

        private static Uri GetMetadataUri(IConfiguration config, string idp)
        {
            ArgumentNullException.ThrowIfNull(config);
            ArgumentException.ThrowIfNullOrEmpty(idp);

            string? uriString = config[$"Saml2:{idp}:IdPMetadata"]
                ?? throw new InvalidOperationException("IdP metadata URI is missing from configuration.");
            return new Uri(uriString);
        }

        public static async Task<SamlConfig> GetSamlSignonConfig(this IConfiguration config, IHttpClientFactory httpClientFactory, string idp, string returnUrl)
        {
            var entityDescriptor = await GetEntiyDescriptor(config, httpClientFactory, idp);

            var idpSsoDescriptor = entityDescriptor.IdPSsoDescriptor
                ?? throw new InvalidOperationException("IdP single sign-on descriptor not found in metadata.");

            var signonService = idpSsoDescriptor.SingleSignOnServices.FirstOrDefault()
                ?? throw new InvalidOperationException("No single sign-on service was found in metadata.");

            var saml2Config = GetSaml2Configuration(config, idp);
            saml2Config.SingleSignOnDestination = signonService.Location;
            saml2Config.SignatureValidationCertificates.AddRange(idpSsoDescriptor.SigningCertificates);
            saml2Config.CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None;
  
            var samlConfig = new SamlConfig(
                saml2Config,
                GetSaml2Binding(signonService.Binding)
            );

            samlConfig.Binding.SetRelayStateQuery(
                new Dictionary<string, string> { { "ReturnUrl", returnUrl } }
            );

            return samlConfig;
        }

        public static async Task<SamlConfig?> GetSamlLogoutConfig(this IConfiguration config, IHttpClientFactory httpClientFactory, string idp)
        {
            var entityDescriptor = await GetEntiyDescriptor(config, httpClientFactory, idp);

            var idpSsoDescriptor = entityDescriptor.IdPSsoDescriptor
                ?? throw new InvalidOperationException("IdP single sign-on descriptor not found in metadata.");

            var logoutService = idpSsoDescriptor.SingleLogoutServices.FirstOrDefault();

            if (logoutService ==  null)
            {
                return null;
            }

            var saml2Config = GetSaml2Configuration(config, idp);
            saml2Config.SingleLogoutDestination = logoutService.Location;
            saml2Config.SignatureValidationCertificates.AddRange(idpSsoDescriptor.SigningCertificates);
            saml2Config.CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None;

            return new SamlConfig(
                saml2Config,
                GetSaml2Binding(logoutService.Binding)
            );
        }

        public static SamlConfig GetSamlAssertionConsumerConfig(this IConfiguration config, string idp)
        {
            var saml2Config = GetSaml2Configuration(config, idp);

            return new SamlConfig(
                saml2Config,
                GetSaml2Binding(PostBinding)
            );
        }
    }
}

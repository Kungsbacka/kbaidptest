using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using ITfoxtec.Identity.Saml2;

namespace kbaidptest
{
    public static class SamlConfig
    {
        public static Saml2Configuration GetSamlConfig(this IConfiguration config, string idp)
        {
            if (idp == null) throw new ArgumentNullException(nameof(idp));
            var samlConfig = new Saml2Configuration();
            config.Bind($"Saml2:{idp}", samlConfig);
            samlConfig.AllowedAudienceUris.Add(samlConfig.Issuer);
            EntityDescriptor entityDescriptor = new();
            entityDescriptor.ReadIdPSsoDescriptorFromUrl(new Uri(config[$"Saml2:{idp}:IdPMetadata"]));
            if (entityDescriptor.IdPSsoDescriptor == null)
            {
                throw new Exception("IdPSsoDescriptor not loaded from metadata.");
            }
            samlConfig.SingleSignOnDestination = entityDescriptor.IdPSsoDescriptor.SingleSignOnServices.First().Location;
            samlConfig.SignatureValidationCertificates.AddRange(entityDescriptor.IdPSsoDescriptor.SigningCertificates);
            samlConfig.CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None;
            return samlConfig;
        }
    }
}

using System.Security.Claims;

namespace kbaidptest
{

    public static class ClaimsTransform
    {
        private static readonly string groupClaimType = "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid";


        public static ClaimsPrincipal Transform(ClaimsPrincipal incomingPrincipal)
        {
            if (incomingPrincipal.Identity == null || !incomingPrincipal.Identity.IsAuthenticated)
            {
                return incomingPrincipal;
            }
            return CreateClaimsPrincipal(incomingPrincipal);
        }

        private static ClaimsPrincipal CreateClaimsPrincipal(ClaimsPrincipal incomingPrincipal)
        {
            if (incomingPrincipal == null || incomingPrincipal.Identity == null)
            {
                throw new ArgumentNullException(nameof(incomingPrincipal));
            }
            var claims = new List<Claim>();
            int groupClaimCount = incomingPrincipal.Claims.Where(c => c.Type == groupClaimType).Count();
            claims.AddRange(incomingPrincipal.Claims.Where(c => c.Type != groupClaimType));
            if (groupClaimCount > 0)
            {
                claims.Add(new Claim(groupClaimType, $"({groupClaimCount} claims)"));
            }
            return new ClaimsPrincipal(new ClaimsIdentity(claims, incomingPrincipal.Identity.AuthenticationType, ClaimTypes.NameIdentifier, ClaimTypes.Role)
            {
                BootstrapContext = ((ClaimsIdentity)incomingPrincipal.Identity).BootstrapContext
            });
        }
    }
}

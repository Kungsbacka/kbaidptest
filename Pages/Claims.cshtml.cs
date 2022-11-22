using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Authorization;

namespace kbaidptest.Pages
{
    [Authorize]
    public class ClaimsModel : PageModel
    {
        private readonly ILogger<ClaimsModel> _logger;
        public ClaimDescription ClaimDescription { get; }

        public ClaimsModel(ILogger<ClaimsModel> logger, ClaimDescription claimDescription)
        {
            _logger = logger;
            ClaimDescription = claimDescription;
        }

        public void OnGet()
        {

        }
    }
}
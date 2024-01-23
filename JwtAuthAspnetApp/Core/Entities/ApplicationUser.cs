using Microsoft.AspNetCore.Identity;

namespace JwtAuthAspnetApp.Core.Entities
{
    public class ApplicationUser: IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
    }
}

using System.ComponentModel.DataAnnotations;

namespace JwtAuthAspnetApp.Core.DataModel
{
    public class UpdatePermissionModel
    {
        [Required(ErrorMessage = "UserName is required")]
        public string UserName { get; set; }
    }
}
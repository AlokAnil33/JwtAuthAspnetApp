using JwtAuthAspnetApp.Core.DataModel;
using JwtAuthAspnetApp.Core.DataModels;

namespace JwtAuthAspnetApp.Core.Interfaces
{
    public interface IAuthService
    {
        Task<AuthServiceResponseModel> SeedRolesAsync();
        Task<AuthServiceResponseModel> RegisterAsync(RegisterModel registerModel);
        Task<AuthServiceResponseModel> LoginAsync(LoginModel loginModel);
        Task<AuthServiceResponseModel> MakeAdminAsync(UpdatePermissionModel updatePermissionModel);
        Task<AuthServiceResponseModel> MakeOwnerAsync(UpdatePermissionModel updatePermissionModel);
    }
}

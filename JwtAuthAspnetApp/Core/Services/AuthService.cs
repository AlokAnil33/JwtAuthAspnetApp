using JwtAuthAspnetApp.Core.DataModel;
using JwtAuthAspnetApp.Core.DataModels;
using JwtAuthAspnetApp.Core.Entities;
using JwtAuthAspnetApp.Core.Interfaces;
using JwtAuthAspnetApp.Core.OtherObjects;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtAuthAspnetApp.Core.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly IConfiguration configuration;

        public AuthService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
            this.configuration = configuration;
        }
        public async Task<AuthServiceResponseModel> LoginAsync(LoginModel loginModel)
        {
            var user = await userManager.FindByNameAsync(loginModel.UserName);
            if (user is null)
                return new AuthServiceResponseModel()
                {
                    IsSucceed = false,
                    Message = "Invalid Credentials"
                };
            var isPasswordCorrect = await userManager.CheckPasswordAsync(user, loginModel.Password);
            if (!isPasswordCorrect)
                return new AuthServiceResponseModel()
                {
                    IsSucceed = false,
                    Message = "Invalid Credentials"
                };
            var userRoles = await userManager.GetRolesAsync(user);
            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim("JWTID", Guid.NewGuid().ToString()),
                new Claim("FirstName",user.FirstName),
                new Claim("LastName",user.LastName)
            };
            foreach (var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }
            var token = GenerateNewJsonWebToken(authClaims);
            return new AuthServiceResponseModel()
            {
                IsSucceed = true,
                Message = token
            };
        }
        private string GenerateNewJsonWebToken(List<Claim> claims)
        {
            var authSecret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:Secret"]));
            var tokenObject = new JwtSecurityToken(
                issuer: configuration["JWT:ValidIssuer"],
                audience: configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(1),
                claims: claims,
                signingCredentials: new SigningCredentials(authSecret, SecurityAlgorithms.HmacSha256)
                );
            string token = new JwtSecurityTokenHandler().WriteToken(tokenObject);
            return token;
        }
        public async Task<AuthServiceResponseModel> MakeAdminAsync(UpdatePermissionModel updatePermissionModel)
        {
            var user = await userManager.FindByNameAsync(updatePermissionModel.UserName);
            if (user is null)
                return new AuthServiceResponseModel()
                {
                    IsSucceed = false,
                    Message = "Invalid UserName"
                };
            await userManager.AddToRoleAsync(user, StaticUserRoles.ADMIN);
            return new AuthServiceResponseModel()
            {
                IsSucceed = true,
                Message = "User is now an Admin"
            };
        }

        public async Task<AuthServiceResponseModel> MakeOwnerAsync(UpdatePermissionModel updatePermissionModel)
        {
            var user = await userManager.FindByNameAsync(updatePermissionModel.UserName);
            if (user is null)
                return new AuthServiceResponseModel()
                {
                    IsSucceed = false,
                    Message = "Invalid UserName"
                };
            await userManager.AddToRoleAsync(user, StaticUserRoles.OWNER);
            return new AuthServiceResponseModel()
            {
                IsSucceed = true,
                Message = "User is now an Owner"
            };
        }

        public async Task<AuthServiceResponseModel> RegisterAsync(RegisterModel registerModel)
        {
            var isExistUser = await userManager.FindByNameAsync(registerModel.UserName);
            if (isExistUser != null)
                return new AuthServiceResponseModel()
                {
                    IsSucceed = false,
                    Message = "UserName already exists"
                };
            ApplicationUser newUser = new ApplicationUser()
            {
                FirstName = registerModel.FirstName,
                LastName = registerModel.LastName,
                Email = registerModel.EMail,
                UserName = registerModel.UserName,
                SecurityStamp = Guid.NewGuid().ToString(),
            };

            var createUserResult = await userManager.CreateAsync(newUser, registerModel.Password);
            if (!createUserResult.Succeeded)
            {
                var errorString = "User Creation failed because :";
                foreach (var error in createUserResult.Errors)
                {
                    errorString += "\n#" + error.Description;
                }
                return new AuthServiceResponseModel()
                {
                    IsSucceed = false,
                    Message = errorString
                };
            }
            //Add default USER role to all users
            await userManager.AddToRoleAsync(newUser, StaticUserRoles.USER);
            return new AuthServiceResponseModel()
            {
                IsSucceed = true,
                Message = "User created Succesfully"
            };
        }

        public async Task<AuthServiceResponseModel> SeedRolesAsync()
        {
            bool isOwnerRoleExists = await roleManager.RoleExistsAsync(StaticUserRoles.OWNER);
            bool isAdminRoleExists = await roleManager.RoleExistsAsync(StaticUserRoles.ADMIN);
            bool isUserRoleExists = await roleManager.RoleExistsAsync(StaticUserRoles.USER);

            if (isOwnerRoleExists && isAdminRoleExists && isUserRoleExists)
                return new AuthServiceResponseModel()
                {
                    IsSucceed = true,
                    Message = "Role Seeding already done"
                };

            await roleManager.CreateAsync(new IdentityRole(StaticUserRoles.USER));
            await roleManager.CreateAsync(new IdentityRole(StaticUserRoles.ADMIN));
            await roleManager.CreateAsync(new IdentityRole(StaticUserRoles.OWNER));

            return new AuthServiceResponseModel()
            {
                IsSucceed = true,
                Message = "Role Seeding done successfully"
            };
        }
    }
}

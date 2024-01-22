using JwtAuthAspnetApp.Core.DataModel;
using JwtAuthAspnetApp.Core.OtherObjects;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;


namespace JwtAuthAspnetApp.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly IConfiguration configuration;

        public AuthController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
            this.configuration = configuration;
        }


        //seeding user roles 
        [HttpPost]
        [Route("seed-roles")]
        public async Task<IActionResult> SeedRoles()
        {
            bool isOwnerRoleExists = await roleManager.RoleExistsAsync(StaticUserRoles.OWNER);
            bool isAdminRoleExists = await roleManager.RoleExistsAsync(StaticUserRoles.ADMIN);
            bool isUserRoleExists = await roleManager.RoleExistsAsync(StaticUserRoles.USER);

            if (isOwnerRoleExists && isAdminRoleExists && isUserRoleExists)
                return Ok("roles seeding is already done");

            await roleManager.CreateAsync(new IdentityRole(StaticUserRoles.USER));
            await roleManager.CreateAsync(new IdentityRole(StaticUserRoles.ADMIN));
            await roleManager.CreateAsync(new IdentityRole(StaticUserRoles.OWNER));

            return Ok("role seeding successfull");
        }

        //Route -> Register
        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel registerModel)
        {
            var isExistUser = await userManager.FindByNameAsync(registerModel.UserName);
            if (isExistUser != null)
                return BadRequest("UserName already exists");
            IdentityUser newUser = new IdentityUser()
            {
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
                return BadRequest(errorString);
            }
            //Add default USER role to all users
            await userManager.AddToRoleAsync(newUser, StaticUserRoles.USER);
            return Ok("User craeted succesfully");
        }

        //Route -> Login
        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            var user = await userManager.FindByNameAsync(loginModel.UserName);
            if (user is null)
                return Unauthorized("Invalid Credentials");
            var isPasswordCorrect = await userManager.CheckPasswordAsync(user, loginModel.Password);
            if (!isPasswordCorrect)
                return Unauthorized("Invalid Credentials");
            var userRoles = await userManager.GetRolesAsync(user);
            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim("JWTID", Guid.NewGuid().ToString())
            };
            foreach (var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }
            var token = GenerateNewJsonWebToken(authClaims);
            return Ok(token);
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

        //route -> make user -> admin
        [HttpPost]
        [Route("make-admin")]
        public async Task<IActionResult> MakeAdmin([FromBody] UpdatePermissionModel updatePermissionModel)
        {
            var user = await userManager.FindByNameAsync(updatePermissionModel.UserName);
            if (user is null)
                return BadRequest("Invalid Username");
            await userManager.AddToRoleAsync(user, StaticUserRoles.ADMIN);
            return Ok("User is now an Admin");
        }

        //route -> make user -> owner
        [HttpPost]
        [Route("make-owner")]
        public async Task<IActionResult> MakeOwner([FromBody] UpdatePermissionModel updatePermissionModel)
        {
            var user = await userManager.FindByNameAsync(updatePermissionModel.UserName);
            if (user is null)
                return BadRequest("Invalid Username");
            await userManager.AddToRoleAsync(user, StaticUserRoles.OWNER);
            return Ok("User is now an Owner");
        }


    }
}

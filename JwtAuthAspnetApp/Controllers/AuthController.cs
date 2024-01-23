using JwtAuthAspnetApp.Core.DataModel;
using JwtAuthAspnetApp.Core.Entities;
using JwtAuthAspnetApp.Core.Interfaces;
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

        //private readonly UserManager<ApplicationUser> userManager;
        //private readonly RoleManager<IdentityRole> roleManager;
        //private readonly IConfiguration configuration;

        //public AuthController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        //{
        //    this.userManager = userManager;
        //    this.roleManager = roleManager;
        //    this.configuration = configuration;
        //}

        private readonly IAuthService authService;
        public AuthController(IAuthService authService)
        {
            this.authService = authService;
        }


        //seeding user roles 
        [HttpPost]
        [Route("seed-roles")]
        public async Task<IActionResult> SeedRoles()
        {
            var seedRoles = await authService.SeedRolesAsync();
            return Ok(seedRoles);
        }

        //Route -> Register
        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel registerModel)
        {
            var registerResult = await authService.RegisterAsync(registerModel);
            if(registerResult.IsSucceed)
            return Ok(registerResult);
            return BadRequest(registerResult);
        }

        //Route -> Login
        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
           var loginResult = await authService.LoginAsync(loginModel);
            if (loginResult.IsSucceed)
                return Ok(loginResult); 
            return Unauthorized(loginResult);
        }

        //route -> make user -> admin
        [HttpPost]
        [Route("make-admin")]
        public async Task<IActionResult> MakeAdmin([FromBody] UpdatePermissionModel updatePermissionModel)
        {
            var operationResult = await authService.MakeAdminAsync(updatePermissionModel);
            if(operationResult.IsSucceed)
                return Ok(operationResult);
            return BadRequest(operationResult);
        }

        //route -> make user -> owner
        [HttpPost]
        [Route("make-owner")]
        public async Task<IActionResult> MakeOwner([FromBody] UpdatePermissionModel updatePermissionModel)
        {
            var operationResult = await authService.MakeOwnerAsync(updatePermissionModel);
            if (operationResult.IsSucceed)
                return Ok(operationResult);
            return BadRequest(operationResult);
        }


    }
}

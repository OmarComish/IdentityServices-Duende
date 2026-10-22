using IdentityService.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityService.Controllers
{
    [ApiController]
    [Route("api/[Controller]")]
    public class AccountController: ControllerBase
    {
        private readonly ILogger<AccountController> _logger;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        public AccountController(ILogger<AccountController> logger, 
        UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager,
         SignInManager<ApplicationUser> signInManager)
        {
            _logger = logger;
            _roleManager = roleManager;
            _userManager = userManager;
            _signInManager = signInManager;
        }
        [AllowAnonymous]
        [HttpPost("register")]
        public async Task<ActionResult> Register([FromBody] RegisterUserRequest request)
        {
            if(!ModelState.IsValid)
                return BadRequest(ModelState);
            var user = new ApplicationUser
            {
                UserName = request.UserName,
                Email = request.Email
            };

            var result = await _userManager.CreateAsync(user, request.Password);
            if(!result.Succeeded)
               return BadRequest(new {errors = result.Errors.Select(e =>new {e.Code, e.Description})});

            //Assign default role on registration
            await _userManager.AddToRoleAsync(user, "Trustee");

            return Ok(new {Message = $"User {request.UserName} registred successfully", Status ="success"});
        }
        [AllowAnonymous]
        [HttpPost("assign-roles")]
        public async Task<IActionResult> AssignRole([FromBody] AssignRoleRequest request)
        {
            var user = await _userManager.FindByNameAsync(request.Username);
            if(user == null)
              return NotFound(new {Message =$"User {request.Username} not found"});
            
            if(!await _roleManager.RoleExistsAsync(request.Role))
              return BadRequest(new {Message= $"Roke '{request.Role}' does not exist"});

            if(await _userManager.IsInRoleAsync(user, request.Role))
              return BadRequest(new {Message ="User already assigned this rile"});
            
            var result = await _userManager.AddToRoleAsync(user, request.Role);

            if(!result.Succeeded)
              return BadRequest(new {errors = result.Errors.Select(e =>new {e.Code, e.Description})});

            return Ok(new {message =$"Role '{request.Role}' assigned to  '{request.Username}' successfully"});
        }
        [AllowAnonymous]
        [HttpPost("signin")]
        public async Task<IActionResult> SignIn([FromBody] LogInRequest request)
        {
            if(!ModelState.IsValid)
              return BadRequest(ModelState);
            var user = await _userManager.FindByNameAsync(request.Username);

            if(user == null)
              return Unauthorized(new LogInResponse{Status="error",Message="Invalid username or password"});
            
            var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, false);

            if(!result.Succeeded)
              return Unauthorized( new LogInResponse{Status="error",Message="Invalid username or password"});

            var roles = await _userManager.GetRolesAsync(user);

            return Ok(new LogInResponse
            {
              Status = "success",
              Message ="Login successful",
              UserId = user.Id,
              Username = user.UserName,
              Email = user.Email,
              Roles = roles
            });
        }

        [AllowAnonymous]
        [HttpGet("{email}")]
        public async Task<IActionResult> GetUserDetailsByEmail(string email)
         {
            if(string.IsNullOrEmpty(email))
               return BadRequest("Null or invalid email");
             var response = await _userManager.FindByEmailAsync(email);
             return Ok(response);
         }
    }
}
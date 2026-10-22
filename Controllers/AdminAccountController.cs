using Duende.IdentityServer;
using IdentityService.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityService.Controllers;

[ApiController]
[Route("api/admin/accounts")]
[Authorize(IdentityServerConstants.LocalApi.PolicyName)]
public class AdminAccountController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;

    public AdminAccountController(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }

    public record CreateAccountRequest(string UserName, string Email, string Password);
    public record ResetPasswordRequest(string NewPassword);

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateAccountRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.UserName) ||
            string.IsNullOrWhiteSpace(request.Email) ||
            string.IsNullOrEmpty(request.Password))
            return BadRequest(new { message = "userName, email and password are required" });

        var user = new ApplicationUser { UserName = request.UserName, Email = request.Email };
        var result = await _userManager.CreateAsync(user, request.Password);
        return result.Succeeded ? StatusCode(201, new { message = "Account created" }) : Failed(result);
    }

    [HttpPut("{username}/password")]
    public async Task<IActionResult> ResetPassword(string username, [FromBody] ResetPasswordRequest request)
    {
        if (string.IsNullOrEmpty(request.NewPassword))
            return BadRequest(new { message = "newPassword is required" });

        var user = await _userManager.FindByNameAsync(username);
        if (user is null)
            return NotFound(new { message = $"Account '{username}' not found" });

        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        var result = await _userManager.ResetPasswordAsync(user, token, request.NewPassword);
        if (!result.Succeeded)
            return Failed(result);

        await _userManager.ResetAccessFailedCountAsync(user);
        await _userManager.SetLockoutEndDateAsync(user, null);
        return NoContent();
    }

    [HttpDelete("{username}")]
    public async Task<IActionResult> Delete(string username)
    {
        var user = await _userManager.FindByNameAsync(username);
        if (user is null)
            return NoContent();   // idempotent: already gone

        var result = await _userManager.DeleteAsync(user);
        return result.Succeeded ? NoContent() : Failed(result);
    }

    private IActionResult Failed(IdentityResult result) =>
        BadRequest(new { errors = result.Errors.Select(e => new { e.Code, e.Description }) });
}
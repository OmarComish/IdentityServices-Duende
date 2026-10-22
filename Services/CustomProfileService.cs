using System.Security.Claims;
using Duende.IdentityModel;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using IdentityService.Models;
using Microsoft.AspNetCore.Identity;

namespace IdentityService;

public class CustomProfileService : IProfileService
{
    private readonly UserManager<ApplicationUser> _userManager;
    public CustomProfileService(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }
    public async Task GetProfileDataAsync(ProfileDataRequestContext context)
    {
        var user = await _userManager.GetUserAsync(context.Subject);

        if(user == null) return;
        var claims = new List<Claim>
        {
            new Claim("username", user.UserName),
            new Claim("Id", user.Id.ToString())
        };
        
        //Add name claim from existing claims if available, otherwise ass usernam claim
        var existingClaims = await _userManager.GetClaimsAsync(user);
        var nameClaim = existingClaims.FirstOrDefault(x=>x.Type == JwtClaimTypes.Name);

        if(nameClaim != null)
        
            claims.Add(nameClaim);
        else
            claims.Add(new Claim(JwtClaimTypes.Name, user.UserName?? ""));


        context.IssuedClaims.AddRange(claims);
        //context.IssuedClaims.Add(existingClaims.FirstOrDefault(x => x.Type == JwtClaimTypes.Name));
    }

    public Task IsActiveAsync(IsActiveContext context)
    {
        //var user = await _userManager.GetUserAsync(context.Subject);
        //context.IsActive = user!= null && !user.LockoutEnabled;
        return Task.CompletedTask;
        
    }
}
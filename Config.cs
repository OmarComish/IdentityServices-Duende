using Duende.IdentityServer;
using Duende.IdentityServer.Models;

namespace IdentityService;

public static class Config
{

    public static IEnumerable<ApiResource> ApiResources =>
    new ApiResource[]
    {
        new ApiResource("casemanagementApi", "Case Management API")
        {
            Scopes = { "casemanagementApp" }
        }
    };
    public static IEnumerable<IdentityResource> IdentityResources =>
        new IdentityResource[]
        {
            new IdentityResources.OpenId(),
            new IdentityResources.Profile(),
        };

    public static IEnumerable<ApiScope> ApiScopes =>
        new ApiScope[]
        {
            new ApiScope("casemanagementApp", "Tripple C app full access"),
            new ApiScope(IdentityServerConstants.LocalApi.ScopeName)
        };

    public static IEnumerable<Client> Clients =>
        new Client[]
        {
           new Client
           {
             ClientId = "postman",
             ClientName = "Postman",
             AllowedScopes = {"openid","profile","casemanagementApp"},
             RedirectUris ={"https://www.getpostman.com/auth2/callback"},
             ClientSecrets = new []{new Secret("NotASecret".Sha256())},
             AllowedGrantTypes = {GrantType.ResourceOwnerPassword}
            },
             new Client
           {
             ClientId = "hotel-api-admin",
             ClientName = "Hotel API (account administration)",
             ClientSecrets = { new Secret("DevAdminSecret-ChangeMe".Sha256()) },
             AllowedGrantTypes = GrantTypes.ClientCredentials,
             AllowedScopes = { IdentityServerConstants.LocalApi.ScopeName }
           }
        };
}

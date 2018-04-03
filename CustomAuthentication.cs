using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

public static class CustomAuthExtensions
{
    public static AuthenticationBuilder AddCustomAuth(this AuthenticationBuilder builder, Action<CustomAuthOptions> configureOptions)
    {
        return builder.AddScheme<CustomAuthOptions, CustomAuthHandler>("Custom Scheme", "Custom Auth", configureOptions);
    }
}

public class CustomAuthOptions: AuthenticationSchemeOptions
{
    public CustomAuthOptions()
    {

    }
}

internal class CustomAuthHandler : AuthenticationHandler<CustomAuthOptions>
{
    public CustomAuthHandler(IOptionsMonitor<CustomAuthOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
    {
        // store custom services here...
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        string chen = Request.Query["chen"];

        if(chen == null)
        {
            return await Task.FromResult(AuthenticateResult.Fail("Auth Failed!"));
        }

        Console.WriteLine(chen);


        var claims = new List<Claim>();
        claims.Add(new Claim(ClaimTypes.Name, "admin"));
        claims.Add(new Claim(ClaimTypes.NameIdentifier, "admin"));
        claims.Add(new Claim(ClaimTypes.Role, "admin"));
        ClaimsIdentity claimsIdentity = new ClaimsIdentity(claims);
        ClaimsPrincipal claimsPrincipal = new ClaimsPrincipal(claimsIdentity);
                
        return AuthenticateResult.Success(new AuthenticationTicket(claimsPrincipal,
            new AuthenticationProperties(), "ApiKey"));
    }
}

public class TokenAuthenticationFilter : Attribute, IAuthorizationFilter
{

    public void OnAuthorization(AuthorizationFilterContext context)
    {
        Console.WriteLine("AuthorizationAsync Filter Executed");

        var controllerActionDescriptor = (ControllerActionDescriptor)context.ActionDescriptor;

        if(controllerActionDescriptor != null)
        {
            //var isDefined = controllerActionDescriptor.MethodInfo.GetCustomAttributes(true)
            //    .Any(x => x.GetType().Equals(typeof(ChenFilterAttribute)));
            //Console.WriteLine("isDefined Count " + controllerActionDescriptor.MethodInfo.GetCustomAttributes(typeof(ChenFilterAttribute), false).Count());
            
            var isDefined = controllerActionDescriptor.MethodInfo.GetCustomAttribute(typeof(ChenFilterAttribute), false);
            if(isDefined != null)
            {
                return;
            }
        }
        context.Result = new BadRequestObjectResult("Bad Request!");
        
    }

    public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        await Task.Run(() => { Console.WriteLine("Kuy"); });
        context.Result = new BadRequestObjectResult("Bad Requestz!");

    }
}

public class ChenFilterAttribute : Attribute, IActionFilter
{
    public void OnActionExecuted(ActionExecutedContext context)
    {
        //Console.WriteLine("ActionFilterAttribute Executed!");]
    }

    public void OnActionExecuting(ActionExecutingContext context)
    {
        Console.WriteLine("ActionFilterAttribute Executed!");
    }
}
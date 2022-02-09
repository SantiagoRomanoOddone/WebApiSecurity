using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using WebApiSecurity.Controllers;

namespace WebApiSecurity.Middleware
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
    public class AuthorizeAttribute : Attribute, IAuthorizationFilter
    {
        //is a simple custom authorize attribute that checks if the  custom JWT middleware succeeded by checking if an account object was attached to the current http context for the request (context.HttpContext.Items["User"]).
        public void OnAuthorization(AuthorizationFilterContext context)
        {
            var account = (LoginModel)context.HttpContext.Items["User"];
            if (account == null)
            {
                // not logged in
                context.Result = new JsonResult(new { message = "Unauthorized" }) { StatusCode = StatusCodes.Status401Unauthorized };
            }
        }
    }
}

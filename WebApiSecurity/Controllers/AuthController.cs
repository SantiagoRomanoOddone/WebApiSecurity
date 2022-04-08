using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using OpenTelemetry;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using WebApiSecurity.Services;

namespace WebApiSecurity.Controllers
{
    [Route("v1/minipompom/jwt")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly IUserService _userService;
        public AuthController(IConfiguration configuration, IUserService userService)
        {
            _configuration = configuration;
            _userService = userService;
        }
        [AllowAnonymous]
        [HttpPost(nameof(Auth))]
        public IActionResult Auth([FromBody] LoginModel data)
        {
            var inputBody = new InputBody
            {
                method = HttpContext.Request.Method,
                channel = "sucursal",
                path = HttpContext.Request.Path
            };
            bool isValid = _userService.IsValidUserInformation(data);
            if (isValid)
            {
                var tokenString = GenerateJwtToken(data.UserName, inputBody);
                return Ok(new { Token = tokenString, Message = "Success" });
            }
            return BadRequest("Please pass the valid Username and Password");
        }

        //[Authorize(AuthenticationSchemes = Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerDefaults.AuthenticationScheme)]
        [HttpGet(nameof(GetResult))]
        public IActionResult GetResult()
        {
            //var connectionId = Baggage.Current.GetBaggage("ConnectionId");
            //var traceIdentifier = Baggage.Current.GetBaggage("TraceIdentifier");
            

            //using var source = new ActivitySource("ExampleTracer");
            //using var activity = source.StartActivity("In Security Web Api");


            //activity?.SetTag("ConnectionId", connectionId);
            //activity?.SetTag("TraceIdentifier", traceIdentifier);

             
            return Ok("API Validated");
        }

        private string GenerateJwtToken(string userName, InputBody inputBody)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_configuration["Jwt:key"]);

            var claims = new ClaimsIdentity(new[]
            {
                new Claim("id", userName),
                new Claim("input-body", JsonConvert.SerializeObject(inputBody))
            });

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = claims,
                //TODO: Cambiar a 1min una vez finalizada la capacitación para cumplir con los requerimentos del trabajo
                Expires = DateTime.UtcNow.AddHours(12),
                Issuer = _configuration["Jwt:Issuer"],
                Audience = _configuration["Jwt:Audience"],
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }      
    }
    #region JsonProperties  
    /// <summary>  
    /// Json Properties  
    /// </summary>  
    public class LoginModel
    {
        [Required]
        public string UserName { get; set; }
        [Required]
        public string Password { get; set; }
    }
    #endregion

}

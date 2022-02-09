using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using WebApiSecurity.Controllers;

namespace WebApiSecurity.Services
{
    public interface IUserService
    {
        bool IsValidUserInformation(LoginModel model);
        //TODO: VER
        LoginModel GetUserDetails();
    }
}

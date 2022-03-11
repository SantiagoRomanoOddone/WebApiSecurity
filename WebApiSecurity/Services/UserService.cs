using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using WebApiSecurity.Controllers;

namespace WebApiSecurity.Services
{
    public class UserService : IUserService
    {
        public bool IsValidUserInformation(LoginModel model)
        {
            if (model.UserName.Equals("Admin") && model.Password.Equals("Admin123")) return true;
            else return false;
        }
        public LoginModel GetUserDetails()
        {
            return new LoginModel { UserName = "Admin", Password = "Admin123" };
        }
    }
}

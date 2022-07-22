using Online_Assessment_System.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Online_Assessment_System.Interfaces
{
    public interface ITokenService
    {
        public string createToken(PasswordModel passwordModel);
    }
}

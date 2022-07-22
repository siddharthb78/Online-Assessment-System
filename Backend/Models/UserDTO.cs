using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Online_Assessment_System.Models
{
    public class UserDTO
    {
        public UserDTO(string u, string t)
        {
            this.USN = u;
            this.Token = t;
        }
        public string USN { get; set; }

        public string Token { get; set; }
    }
}

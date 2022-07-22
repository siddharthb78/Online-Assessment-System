using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Online_Assessment_System.Models
{
    public class SuperUserDTO
    {
        public SuperUserDTO(string u, string t)
        {
            this.adminId = u;
            this.Token = t;
        }
        public string adminId { get; set; }

        public string Token { get; set; }
    }
}

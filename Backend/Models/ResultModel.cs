using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Online_Assessment_System.Models
{
    public class ResultModel
    {
        public string USN { get; set; }
        public string username { get; set; }
        public int subjectId { get; set; }
        public decimal score { get; set; }
        public string subjectName { get; set; }
    }
}

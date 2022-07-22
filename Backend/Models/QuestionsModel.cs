using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Online_Assessment_System.Models
{
    public class QuestionsModel
    {
       public int subjectId { get; set; }

        public int questionId { get; set; }
        public string question { get; set; }
        public string answer1 { get; set; }
        public string answer2 { get; set; }
        public string answer3 { get; set; }
        public string answer4 { get; set; }
        public string correctAnswer { get; set; }
    }
}

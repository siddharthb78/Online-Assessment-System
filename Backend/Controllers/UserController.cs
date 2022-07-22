using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Online_Assessment_System.Models;
using Online_Assessment_System.Services;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;


namespace Online_Assessment_System.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : Controller
    {
        private readonly IConfiguration _configuration;

        public UserController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        //Paste user model values from Angular -> Database
        [HttpPost]
        [Route("addUserDetails")]
        public bool addUserDetails(User_Model user_obj)
        {
            String query = "insert into userDetails(USN, username, passwordHash, passwordSalt, fullName, email, phoneNumber) " +
                "values(@USN, @username, @passwordHash, @passwordSalt, @fullName, @email, @phoneNumber)";

         
            byte[] passwordHash;
            byte[] passwordSalt;
            using (var hmac = new HMACSHA512())
            {
                 passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(user_obj.password));
                 passwordSalt = hmac.Key;
            }

            //Create Connection
            using (var con = new SqlConnection("Server=DESKTOP-TCQC7VN;Database=OnlineAssessmentSystem;Integrated Security=True"))
            {
                SqlCommand command = new SqlCommand(query, con); //Creates a command using the query

                //Assigning the place holder of the query appropriately

                command.Parameters.Add("@USN", SqlDbType.NVarChar);
                command.Parameters["@USN"].Value = user_obj.USN;


                command.Parameters.Add("@username", SqlDbType.NVarChar);
                command.Parameters["@username"].Value = user_obj.username;

                //To add PasswordHash param
                command.Parameters.Add("@passwordHash", SqlDbType.VarBinary);
                command.Parameters["@passwordHash"].Value = passwordHash;

                //To add PasswordSalt param
                command.Parameters.Add("@passwordSalt", SqlDbType.VarBinary);
                command.Parameters["@passwordSalt"].Value = passwordSalt;

                command.Parameters.Add("@fullName", SqlDbType.NVarChar);
                command.Parameters["@fullName"].Value = user_obj.fullName;

                command.Parameters.Add("@email", SqlDbType.NVarChar);
                command.Parameters["@email"].Value = user_obj.email;

                command.Parameters.Add("@phoneNumber", SqlDbType.NVarChar);
                command.Parameters["@phoneNumber"].Value = user_obj.phoneNumber;

                con.Open(); //Open Connection

                //Execute command
                try
                {
                    //I Need to send the query to the database
                    var res = command.ExecuteNonQuery();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                    return false;
                }
                finally
                {
                    con.Close(); //Close the connection
                }


            }

            return true;
        }

        [HttpPost("Login")]
        public UserDTO loginValidation(LoginModel l)
        {
            PasswordModel p = getUser(l.USN); //Using the username gives us the Password Hash and Password salt from the database.

            if(p == null)
            {
                return null;
            }

            using var hmac = new HMACSHA512(p.passwordSalt);
            var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(l.password));
            for (int i = 0; i < computedHash.Length; i++)
            {
                if (computedHash[i] != p.passwordHash[i])
                    return null;
            }

            return new UserDTO(p.USN, new TokenService(_configuration).createToken(p));
        }

        private PasswordModel getUser(string USN)
        {
            string query = "select passwordHash, passwordSalt, USN from userDetails where USN = @USN";
            PasswordModel passwordDetails = new PasswordModel();
            //Create Connection
            using (var con = new SqlConnection("Server=DESKTOP-TCQC7VN;Database=OnlineAssessmentSystem;Integrated Security=True"))
            {
                SqlCommand command = new SqlCommand(query, con); //Creates a command using the query

                //Assigning the place holder of the query appropriately
                command.Parameters.Add("@USN", SqlDbType.NVarChar);
                command.Parameters["@USN"].Value = USN;


                con.Open(); //Open Connection
                SqlDataReader reader = command.ExecuteReader();
                //Execute command
                try
                { 
                    while (reader.Read())
                    {
                        if (reader.HasRows)
                        { 
                            passwordDetails.passwordHash = (byte[])reader["passwordHash"];
                            passwordDetails.passwordSalt = (byte[])reader["passwordSalt"];
                            passwordDetails.USN = (string)reader["USN"];
                            return passwordDetails;
                        }
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                    return null;
                }
                finally
                {
                    con.Close(); //Close the connection
                }


            }

            return null;
        }


        [HttpPost]
        [Route("addSuperUserDetails")]
        public bool addSuperUserDetails(SuperUserModel superUserObj)
        {
            String query = "insert into superUser(adminId, username, passwordHash, passwordSalt, fullName, email, phoneNumber) " +
                "values(@adminId, @username, @passwordHash, @passwordSalt, @fullName, @email, @phoneNumber)";


            byte[] passwordHash;
            byte[] passwordSalt;
            using (var hmac = new HMACSHA512())
            {
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(superUserObj.password));
                passwordSalt = hmac.Key;
            }

            //Create Connection
            using (var con = new SqlConnection("Server=DESKTOP-TCQC7VN;Database=OnlineAssessmentSystem;Integrated Security=True"))
            {
                SqlCommand command = new SqlCommand(query, con); //Creates a command using the query

                //Assigning the place holder of the query appropriately

                command.Parameters.Add("@adminId", SqlDbType.NVarChar);
                command.Parameters["@adminId"].Value = superUserObj.adminId;


                command.Parameters.Add("@username", SqlDbType.NVarChar);
                command.Parameters["@username"].Value = superUserObj.username;

                //To add PasswordHash param
                command.Parameters.Add("@passwordHash", SqlDbType.VarBinary);
                command.Parameters["@passwordHash"].Value = passwordHash;

                //To add PasswordSalt param
                command.Parameters.Add("@passwordSalt", SqlDbType.VarBinary);
                command.Parameters["@passwordSalt"].Value = passwordSalt;

                command.Parameters.Add("@fullName", SqlDbType.NVarChar);
                command.Parameters["@fullName"].Value = superUserObj.fullName;

                command.Parameters.Add("@email", SqlDbType.NVarChar);
                command.Parameters["@email"].Value = superUserObj.email;

                command.Parameters.Add("@phoneNumber", SqlDbType.NVarChar);
                command.Parameters["@phoneNumber"].Value = superUserObj.phoneNumber;

                con.Open(); //Open Connection

                //Execute command
                try
                {
                    //I Need to send the query to the database
                    var res = command.ExecuteNonQuery();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                    return false;
                }
                finally
                {
                    con.Close(); //Close the connection
                }


            }

            return true;
        }


        private SuperPasswordModel getSuperUser(string adminId)
        {
            string query = "select passwordHash, passwordSalt, adminId from superUser where adminId = @adminId";
            SuperPasswordModel passwordDetails = new SuperPasswordModel();
            //Create Connection
            using (var con = new SqlConnection("Server=DESKTOP-TCQC7VN;Database=OnlineAssessmentSystem;Integrated Security=True"))
            {
                SqlCommand command = new SqlCommand(query, con); //Creates a command using the query

                //Assigning the place holder of the query appropriately
                command.Parameters.Add("@adminId", SqlDbType.NVarChar);
                command.Parameters["@adminId"].Value = adminId;


                con.Open(); //Open Connection
                SqlDataReader reader = command.ExecuteReader();
                //Execute command
                try
                {
                    while (reader.Read())
                    {
                        if (reader.HasRows)
                        {
                            passwordDetails.passwordHash = (byte[])reader["passwordHash"];
                            passwordDetails.passwordSalt = (byte[])reader["passwordSalt"];
                            passwordDetails.adminId = (string)reader["adminId"];
                            return passwordDetails;
                        }
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                    return null;
                }
                finally
                {
                    con.Close(); //Close the connection
                }


            }

            return null;
        }

        [HttpPost("SuperUserLogin")]
        public SuperUserDTO superLoginValidation(SuperLoginModel l)
        {
            SuperPasswordModel p = getSuperUser(l.adminId); //Using the username gives us the Password Hash and Password salt from the database.

            if (p == null)
            {
                return null;
            }

            using var hmac = new HMACSHA512(p.passwordSalt);
            var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(l.password));
            for (int i = 0; i < computedHash.Length; i++)
            {
                if (computedHash[i] != p.passwordHash[i])
                    return null;
            }

            return new SuperUserDTO(p.adminId, new TokenService(_configuration).createToken(p));
        }


        //Paste SubjectModel from angular to database
        [HttpGet("AddSubject/{subjectName}")]
        public bool addSubject(string subjectName)
        {
            String query = "insert into subject(subjectName) values(@subjectName)";
            //Create Connection
            using (var con = new SqlConnection("Server=DESKTOP-TCQC7VN;Database=OnlineAssessmentSystem;Integrated Security=True"))
            {
                SqlCommand command = new SqlCommand(query, con); //Creates a command using the query

                //Assigning the place holder of the query appropriately

                command.Parameters.Add("@subjectName", SqlDbType.NVarChar);
                command.Parameters["@subjectName"].Value = subjectName;

                con.Open(); //Open Connection

                //Execute command
                try
                {
                    //I Need to send the query to the database
                    var res = command.ExecuteNonQuery();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                    return false;
                }
                finally
                {
                    con.Close(); //Close the connection
                }


            }

            return true;
        }

        [HttpPost("AddQuestion")]
        public bool addQuestion(QuestionsModel q)
        {
            string query = "insert into questions(subjectId, question, answer1, answer2, answer3, answer4, correctAnswer)" +
                " values(@subjectId, @question, @answer1, @answer2, @answer3, @answer4, @correctAnswer)";

            //Create Connection
            using (var con = new SqlConnection("Server=DESKTOP-TCQC7VN;Database=OnlineAssessmentSystem;Integrated Security=True"))
            {
                SqlCommand command = new SqlCommand(query, con); //Creates a command using the query

                //Assigning the place holder of the query appropriately

                command.Parameters.Add("@subjectId", SqlDbType.Int);
                command.Parameters["@subjectId"].Value = q.subjectId;

                command.Parameters.Add("@question", SqlDbType.NVarChar);
                command.Parameters["@question"].Value = q.question;

                command.Parameters.Add("@answer1", SqlDbType.NVarChar);
                command.Parameters["@answer1"].Value = q.answer1;

                command.Parameters.Add("@answer2", SqlDbType.NVarChar);
                command.Parameters["@answer2"].Value = q.answer2;

                command.Parameters.Add("@answer3", SqlDbType.NVarChar);
                command.Parameters["@answer3"].Value = q.answer3;

                command.Parameters.Add("@answer4", SqlDbType.NVarChar);
                command.Parameters["@answer4"].Value = q.answer4;

                command.Parameters.Add("@correctAnswer", SqlDbType.NVarChar);
                command.Parameters["@correctAnswer"].Value = q.correctAnswer;

                con.Open(); //Open Connection

                //Execute command
                try
                {
                    //I Need to send the query to the database
                    var res = command.ExecuteNonQuery();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                    return false;
                }
                finally
                {
                    con.Close(); //Close the connection
                }


            }

            return true;

        }

        
        /*User input -> Subject ID
         Output -> 1Q, 4 Options, Correct Answer (For all Questions present)*/
        [HttpGet("GetAllQuestionsForASubject/{id}")]
        public List<QuestionsModel> getAllQuestionsForASubject(int id)
        {
            List<QuestionsModel> res = new List<QuestionsModel>();

            String query = "select * from questions where subjectId = @id";

            using (var con = new SqlConnection("Server=DESKTOP-TCQC7VN;Database=OnlineAssessmentSystem;Integrated Security=True"))
            {
                SqlCommand command = new SqlCommand(query, con); //Creates a command using the query

                //Assigning the parameters appropriately
                command.Parameters.Add("@id", SqlDbType.Int);
                command.Parameters["@id"].Value = id;
                con.Open();
                SqlDataReader reader = command.ExecuteReader();
                try
                {
                    while (reader.Read())
                    {
                        
                        if (reader.HasRows)
                        {
                            QuestionsModel q = new QuestionsModel();

                            q.subjectId = (int)reader["subjectId"];
                            q.questionId = (int)reader["questionId"];
                            q.question = (string)reader["question"];
                            q.answer1 = (string)reader["answer1"];
                            q.answer2 = (string)reader["answer2"];
                            q.answer3 = (string)reader["answer3"];
                            q.answer4 = (string)reader["answer4"];
                            q.correctAnswer = (string)reader["correctAnswer"];

                            res.Add(q);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
                finally
                {
                    // Always call Close when done reading.
                    reader.Close();
                }
            }

            return res;
        }

        /*User input -> USN
        Output -> All results from result table for a given USN*/
        [HttpGet("GetAllResultsForAUSN/{USN}")]
        public List<ResultModel> getAllResultsForAUSN(string USN)
        {
            List<ResultModel> res = new List<ResultModel>();

            string query = "select * from results where USN = @USN";

            using (var con = new SqlConnection("Server=DESKTOP-TCQC7VN;Database=OnlineAssessmentSystem;Integrated Security=True"))
            {
                SqlCommand command = new SqlCommand(query, con); //Creates a command using the query

                //Assigning the parameters appropriately
                command.Parameters.Add("@USN", SqlDbType.NVarChar);
                command.Parameters["@USN"].Value = USN;
                con.Open();
                SqlDataReader reader = command.ExecuteReader();
                try
                {
                    while (reader.Read())
                    {

                        if (reader.HasRows)
                        {
                            ResultModel r = new ResultModel();

                            r.USN = (string)reader["USN"];
                            r.username = (string)reader["username"];
                            r.subjectId = (int)reader["subjectId"];
                            r.score = (decimal)reader["score"];
                            r.subjectName = (string)reader["subjectName"];

                            res.Add(r);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
                finally
                {
                    // Always call Close when done reading.
                    reader.Close();
                }
            }

            return res;
        }

        /*User input -> None
        Output -> All subject Names*/
        [HttpGet("GetAllSubjects")]
       
        public List<SubjectModel> getAllSubjects() //Needs to return a list of <subjectId, subjectName>
        {
            List<SubjectModel> res = new List<SubjectModel>();

            string query = "select subjectId,subjectName from subject";
            using (var con = new SqlConnection("Server=DESKTOP-TCQC7VN;Database=OnlineAssessmentSystem;Integrated Security=True"))
            {
                SqlCommand command = new SqlCommand(query, con); //Creates a command using the query

                //Assigning the parameters appropriately
                con.Open();
                SqlDataReader reader = command.ExecuteReader();
                try
                {
                    while (reader.Read())
                    { 
                        if (reader.HasRows)
                        {
                            SubjectModel s = new SubjectModel();

                            s.subjectId = (int)reader["subjectId"];
                            s.subjectName = (string)reader["subjectName"];
                            res.Add(s);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
                finally
                {
                    // Always call Close when done reading.
                    reader.Close();
                }
            }

            return res;
        }

        /*User input -> Question ID
        Output -> Entire row for a given question ID*/
        [HttpGet("GetRowForAQuestionID/{questionId}")]

        public QuestionsModel getRowForAQuestionID(int questionId)
        {
            QuestionsModel res = new QuestionsModel();

            string query = "select subjectId, question, answer1, answer2, answer3, answer4, correctAnswer from questions where questionId = @questionId";

            using (var con = new SqlConnection("Server=DESKTOP-TCQC7VN;Database=OnlineAssessmentSystem;Integrated Security=True"))
            {
                SqlCommand command = new SqlCommand(query, con); //Creates a command using the query

                //Assigning the parameters appropriately
                command.Parameters.Add("@questionId", SqlDbType.Int);
                command.Parameters["@questionId"].Value = questionId;
                con.Open();
                SqlDataReader reader = command.ExecuteReader();
                try
                {
                    while (reader.Read())
                    {

                        if (reader.HasRows)
                        {

                            res.subjectId = (int)reader["subjectId"];
                            res.question = (string)reader["question"];
                            res.answer1 = (string)reader["answer1"];
                            res.answer2 = (string)reader["answer2"];
                            res.answer3 = (string)reader["answer3"];
                            res.answer4 = (string)reader["answer4"];
                            res.correctAnswer = (string)reader["correctAnswer"];
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
                finally
                {
                    // Always call Close when done reading.
                    reader.Close();
                }
            }

            return res;
        }

        /*User input -> Question ID & Question table object showing the newly to be updated values
        Output -> T/F
        Action required -> Update the row*/
        [HttpPost("UpdateQuestion/{questionId}")]
        public bool updateQuestion(int questionId, [FromBody]QuestionsModel q)
        {
            //QuestionsModel q = new QuestionsModel();
            string query = "update questions set subjectId = @subjectId, question = @question, answer1 = @answer1, answer2 = @answer2, answer3 = @answer3, answer4 = @answer4, correctAnswer = @correctAnswer where questionId = @questionId";

            //Create Connection
            using (var con = new SqlConnection("Server=DESKTOP-TCQC7VN;Database=OnlineAssessmentSystem;Integrated Security=True"))
            {
                SqlCommand command = new SqlCommand(query, con); //Creates a command using the query

                //Assigning the place holder of the query appropriately

                command.Parameters.Add("@subjectId", SqlDbType.Int);
                command.Parameters["@subjectId"].Value = q.subjectId;

                command.Parameters.Add("@question", SqlDbType.NVarChar);
                command.Parameters["@question"].Value = q.question;

                command.Parameters.Add("@answer1", SqlDbType.NVarChar);
                command.Parameters["@answer1"].Value = q.answer1;

                command.Parameters.Add("@answer2", SqlDbType.NVarChar);
                command.Parameters["@answer2"].Value = q.answer2;

                command.Parameters.Add("@answer3", SqlDbType.NVarChar);
                command.Parameters["@answer3"].Value = q.answer3;

                command.Parameters.Add("@answer4", SqlDbType.NVarChar);
                command.Parameters["@answer4"].Value = q.answer4;

                command.Parameters.Add("@correctAnswer", SqlDbType.NVarChar);
                command.Parameters["@correctAnswer"].Value = q.correctAnswer;

                command.Parameters.Add("@questionId", SqlDbType.Int);
                command.Parameters["@questionId"].Value = questionId;

                con.Open(); //Open Connection

                //Execute command
                try
                {
                    //I Need to send the query to the database
                    var res = command.ExecuteNonQuery();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                    return false;
                }
                finally
                {
                    con.Close(); //Close the connection
                }


            }

            return true;

        }


        [HttpPost("UpdateUser/{USN}")]
        public bool updateUser(string USN, [FromBody] User_Model u)
        {

            string query = "update userDetails set USN = @USN, username = @username, fullName = @fullName, email = @email, phoneNumber = @phoneNumber where USN = @USN";

            //Create Connection
            using (var con = new SqlConnection("Server=DESKTOP-TCQC7VN;Database=OnlineAssessmentSystem;Integrated Security=True"))
            {
                SqlCommand command = new SqlCommand(query, con); //Creates a command using the query

                //Assigning the place holder of the query appropriately

                command.Parameters.Add("@USN", SqlDbType.NVarChar);
                command.Parameters["@USN"].Value = u.USN;


                command.Parameters.Add("@username", SqlDbType.NVarChar);
                command.Parameters["@username"].Value = u.username;

                command.Parameters.Add("@fullName", SqlDbType.NVarChar);
                command.Parameters["@fullName"].Value = u.fullName;

                command.Parameters.Add("@email", SqlDbType.NVarChar);
                command.Parameters["@email"].Value = u.email;

                command.Parameters.Add("@phoneNumber", SqlDbType.NVarChar);
                command.Parameters["@phoneNumber"].Value = u.phoneNumber;


                con.Open(); //Open Connection

                //Execute command
                try
                {
                    //I Need to send the query to the database
                    var res = command.ExecuteNonQuery();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                    return false;
                }
                finally
                {
                    con.Close(); //Close the connection
                }


            }

            return true;

        }

        /*User input -> Question ID
        output -> T/F
        Action required -> Delete a row containing Question ID*/

        [HttpGet("DeleteQuestion/{questionId}")]

        public bool deleteQuestion(int questionId)
        {
            string query = "delete questions where questionId = @questionId";

            using (var con = new SqlConnection("Server=DESKTOP-TCQC7VN;Database=OnlineAssessmentSystem;Integrated Security=True"))
            {
                SqlCommand command = new SqlCommand(query, con); //Creates a command using the query

                //Assigning the place holder of the query appropriately

                command.Parameters.Add("@questionId", SqlDbType.Int);
                command.Parameters["@questionId"].Value = questionId;


                con.Open(); //Open Connection

                //Execute command
                try
                {
                    //I Need to send the query to the database
                    var r = command.ExecuteNonQuery();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                    return false;
                }
                finally
                {
                    con.Close(); //Close the connection
                }


            }

            return true;

        }

        /*User input -> Nil
        Output -> Entire Result table for viewing for admin*/

        [HttpGet("ViewResults")]
        public List<ResultModel> viewResults()
        {
            string query = "select * from results ORDER BY USN";

            List<ResultModel> res = new List<ResultModel>();
            using (var con = new SqlConnection("Server=DESKTOP-TCQC7VN;Database=OnlineAssessmentSystem;Integrated Security=True"))
            {
                SqlCommand command = new SqlCommand(query, con); //Creates a command using the query

                //Assigning the parameters appropriately
                con.Open();
                SqlDataReader reader = command.ExecuteReader();
                try
                {
                    while (reader.Read())
                    {
                        if (reader.HasRows)
                        { 
                            ResultModel r = new ResultModel();
                            r.USN = (string)reader["USN"];
                            r.username = (string)reader["username"];
                            r.subjectId = (int)reader["subjectId"];
                            r.score = (decimal)reader["score"];
                            r.subjectName = (string)reader["subjectName"];

                            res.Add(r);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
                finally
                {
                    // Always call Close when done reading.
                    reader.Close();
                }
            }

            return res;

        }

        /*User input - Nil
        Output -> Entire user table*/

        [HttpGet("ViewUserDetails")]
        public List<User_Model> viewUserDetails()
        {
            string query = "select * from userDetails";
            List<User_Model> res = new List<User_Model>();

            using (var con = new SqlConnection("Server=DESKTOP-TCQC7VN;Database=OnlineAssessmentSystem;Integrated Security=True"))
            {
                SqlCommand command = new SqlCommand(query, con); //Creates a command using the query

                //Assigning the parameters appropriately
                con.Open();
                SqlDataReader reader = command.ExecuteReader();
                try
                {
                    while (reader.Read())
                    {
                        if (reader.HasRows)
                        {
                            User_Model r = new User_Model();
                            r.USN = (string)reader["USN"];
                            r.username = (string)reader["username"];
                            r.password = "";
                            r.fullName = (string)reader["fullName"];
                            r.email = (string)reader["email"];
                            r.phoneNumber = (string)reader["phoneNumber"];
                           

                            res.Add(r);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
                finally
                {
                    // Always call Close when done reading.
                    reader.Close();
                }
            }

            return res;
        }

        /*User input -> Subject ID
        Output -> T/F
        Action required -> Delete a row containing the Subject ID
        (This must in turn delete all the questions of the subject) (Cascade ON)*/

        [HttpGet("DeleteSubjectID/{subjectId}")]

        public bool deleteSubjectId(int subjectId)
        {
            string query = "DELETE FROM subject where subjectId = @subjectId";

            using (var con = new SqlConnection("Server=DESKTOP-TCQC7VN;Database=OnlineAssessmentSystem;Integrated Security=True"))
            {
                SqlCommand command = new SqlCommand(query, con); //Creates a command using the query

                //Assigning the place holder of the query appropriately

                command.Parameters.Add("@subjectId", SqlDbType.Int);
                command.Parameters["@subjectId"].Value = subjectId;


                con.Open(); //Open Connection

                //Execute command
                try
                {
                    //I Need to send the query to the database
                    var r = command.ExecuteNonQuery();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                    return false;
                }
                finally
                {
                    con.Close(); //Close the connection
                }


            }

            return true;
        }

        /*User input -> User ID
        Output -> T/F
        Action required -> Delete the row pertaining to the given User ID*/
        [HttpGet("DeleteUSN/{USN}")]

        public bool deleteUSN(string USN)
        {
            string query = "DELETE FROM USERDETAILS where USN = @USN";

            using (var con = new SqlConnection("Server=DESKTOP-TCQC7VN;Database=OnlineAssessmentSystem;Integrated Security=True"))
            {
                SqlCommand command = new SqlCommand(query, con); //Creates a command using the query

                //Assigning the place holder of the query appropriately

                command.Parameters.Add("@USN", SqlDbType.NVarChar);
                command.Parameters["@USN"].Value = USN;


                con.Open(); //Open Connection

                //Execute command
                try
                {
                    //I Need to send the query to the database
                    var r = command.ExecuteNonQuery();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                    return false;
                }
                finally
                {
                    con.Close(); //Close the connection
                }


            }

            return true;
        }


        private string userDetails(string USN)
        {
            string res = "";

            string query = "select username from userDetails where USN = @USN";

            using (var con = new SqlConnection("Server=DESKTOP-TCQC7VN;Database=OnlineAssessmentSystem;Integrated Security=True"))
            {
                SqlCommand command = new SqlCommand(query, con); //Creates a command using the query

                //Assigning the parameters appropriately
                command.Parameters.Add("@USN", SqlDbType.NVarChar);
                command.Parameters["@USN"].Value = USN;

                
                con.Open();
                SqlDataReader reader = command.ExecuteReader();
                try
                {
                    while (reader.Read())
                    {

                        if (reader.HasRows)
                        {
                            res = (string)reader["username"];
                            break;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
                finally
                {
                    // Always call Close when done reading.
                    reader.Close();
                }
            }

            return res;
        }

        [HttpPost("AddResult")]
        public bool addResult(ResultModel res)
        {
            res.username = userDetails(res.USN);
            res.subjectName = subjectDetails(res.subjectId);

            string query = "insert into results values(@USN, @username, @subjectId, @score, @subjectName)";

            //Create Connection
            using (var con = new SqlConnection("Server=DESKTOP-TCQC7VN;Database=OnlineAssessmentSystem;Integrated Security=True"))
            {
                SqlCommand command = new SqlCommand(query, con); //Creates a command using the query

                //Assigning the place holder of the query appropriately

                command.Parameters.Add("@USN", SqlDbType.NVarChar);
                command.Parameters["@USN"].Value = res.USN;

                command.Parameters.Add("@username", SqlDbType.NVarChar);
                command.Parameters["@username"].Value = res.username;

                command.Parameters.Add("@subjectId", SqlDbType.Int);
                command.Parameters["@subjectId"].Value = res.subjectId;

                command.Parameters.Add("@score", SqlDbType.Decimal);
                command.Parameters["@score"].Value = res.score;

                command.Parameters.Add("@subjectName", SqlDbType.NVarChar);
                command.Parameters["@subjectName"].Value = res.subjectName;

                con.Open(); //Open Connection

                //Execute command
                try
                {
                    //I Need to send the query to the database
                    var r = command.ExecuteNonQuery();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                    return false;
                }
                finally
                {
                    con.Close(); //Close the connection
                }


            }

            return true;
        }


        private string subjectDetails(int subjectId)
        {
            string res = "";
            string query = "select subjectName from subject where subjectId = @subjectId";

            using (var con = new SqlConnection("Server=DESKTOP-TCQC7VN;Database=OnlineAssessmentSystem;Integrated Security=True"))
            {
                SqlCommand command = new SqlCommand(query, con); //Creates a command using the query

                //Assigning the parameters appropriately
                command.Parameters.Add("@subjectId", SqlDbType.Int);
                command.Parameters["@subjectId"].Value = subjectId;


                con.Open();
                SqlDataReader reader = command.ExecuteReader();
                try
                {
                    while (reader.Read())
                    {

                        if (reader.HasRows)
                        {
                            res = (string)reader["subjectName"];
                            break;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
                finally
                {
                    // Always call Close when done reading.
                    reader.Close();
                }
            }

            return res;
        }


        [HttpGet("ViewUser/{USN}")]
        public User_Model viewUser(string USN)
        {
            string query = "select * from userDetails where USN = @USN";
            User_Model res = new User_Model();

            using (var con = new SqlConnection("Server=DESKTOP-TCQC7VN;Database=OnlineAssessmentSystem;Integrated Security=True"))
            {
                SqlCommand command = new SqlCommand(query, con); //Creates a command using the query

                //Assigning the parameters appropriately
                //Assigning the parameters appropriately
                command.Parameters.Add("@USN", SqlDbType.NVarChar);
                command.Parameters["@USN"].Value = USN;


                con.Open();
                SqlDataReader reader = command.ExecuteReader();
                try
                {
                    while (reader.Read())
                    {
                        if (reader.HasRows)
                        {
                            res.USN = (string)reader["USN"];
                            res.username = (string)reader["username"];
                            res.password = "";
                            res.fullName = (string)reader["fullName"];
                            res.email = (string)reader["email"];
                            res.phoneNumber = (string)reader["phoneNumber"];

                            break;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
                finally
                {
                    // Always call Close when done reading.
                    reader.Close();
                }
            }

            return res;
        }


        [HttpGet("ViewSuperUser/{adminId}")]
        public SuperUserModel viewSuperUser(string adminId)
        {
            string query = "select * from superUser where adminId = @adminId";
            SuperUserModel res = new SuperUserModel();

            using (var con = new SqlConnection("Server=DESKTOP-TCQC7VN;Database=OnlineAssessmentSystem;Integrated Security=True"))
            {
                SqlCommand command = new SqlCommand(query, con); //Creates a command using the query

                //Assigning the parameters appropriately
                //Assigning the parameters appropriately
                command.Parameters.Add("@adminId", SqlDbType.NVarChar);
                command.Parameters["@adminId"].Value = adminId;


                con.Open();
                SqlDataReader reader = command.ExecuteReader();
                try
                {
                    while (reader.Read())
                    {
                        if (reader.HasRows)
                        {
                            res.adminId = (string)reader["adminId"];
                            res.username = (string)reader["username"];
                            res.password = "";
                            res.fullName = (string)reader["fullName"];
                            res.email = (string)reader["email"];
                            res.phoneNumber = (string)reader["phoneNumber"];

                            break;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
                finally
                {
                    // Always call Close when done reading.
                    reader.Close();
                }
            }

            return res;
        }

        [HttpGet("getSubjectName/{subjectId}")]
        public string getSubjectName(int subjectId)
        {
            return subjectDetails(subjectId);
        }


    }
}

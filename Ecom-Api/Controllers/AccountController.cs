using Ecom_Api.Models;
using Ecom_Api.ModelViews;
using Ecom_Api.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;

namespace Ecom_Api.Controllers
{   
    [AllowAnonymous]
    [Route("[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {

        private readonly ApplicationDb _db;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<ApplicationRole> _roleManager;
       

        public AccountController(ApplicationDb db,UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager, RoleManager<ApplicationRole> roleManager)
        {
           _db = db;
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
           
        }
        //https://localhost:44395/Account/Register
        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register(RegisterModel model)
        {
            if (model == null)
            {
                return NotFound();
            }
            if (ModelState.IsValid)
            {
                if (IsEmailExists(model.Email))
                {
                    return BadRequest("Email is Used");
                }
                if (!IsEmailValid(model.Email))
                {
                    return BadRequest("Email is Not Valid!!");
                }
                if (IsUserNameExists(model.UserName))
                {
                    return BadRequest("UserName is Used");
                   }
                var user = new ApplicationUser
                {
                    Email = model.Email,
                    UserName=model.UserName,
                };


                var result = await _userManager.CreateAsync(user,model.Password);
               
                //send email confirm
                if (result.Succeeded)
                {
                    var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    var confirmLinkASP = Url.Action("RegisterationConfirm", "Account", new
                    { ID = user.Id, Token = HttpUtility.UrlEncode(token) }, Request.Scheme );

                    var encodeToken = Encoding.UTF8.GetBytes(token);
                    var newToken = WebEncoders.Base64UrlEncode(encodeToken);
                    var confirmLink = $"http://localhost:4200/ConfirmPassword?ID={user.Id}&Token={newToken}";
                  //  var txt = "please confirm your registeration at our site";
                  var link = "<a href=\"" + confirmLink + "\">Confirm Registeration</a>";
                    //var title = "Registeration Confirm";
                  //  if(await SendGridAPI.Execute(user.Email, user.UserName, txt, link, title))
                   // {
                        return StatusCode(StatusCodes.Status200OK);
                //    }
                }
                else
                {
                    return BadRequest(result.Errors);
                }
            }
            return StatusCode(StatusCodes.Status400BadRequest);
        }

        private bool IsUserNameExists(string userName)
        {
            return _db.Users.Any(x => x.UserName == userName);
        }

        private bool IsEmailExists(string email)
        {
            return _db.Users.Any(x => x.Email == email);
        }

        private bool IsEmailValid(string email)
        {
            Regex em = new Regex(@"\w+\@\w+.com|\w+@\w+.net");
            if (em.IsMatch(email))
            {
                return true;
            }
            return false;
        }

        [HttpGet]
        [Route("RegisterationConfirm")]
        public async Task<IActionResult> RegisterationConfirm(string ID,string Token)
        {
            if(string.IsNullOrEmpty(ID) ||string.IsNullOrEmpty(Token))
                return NotFound();
            var user = await _userManager.FindByIdAsync(ID);
            if (user == null)
                return NotFound();

            var newToken = WebEncoders.Base64UrlDecode(Token);
            var encodeToken = Encoding.UTF8.GetString(newToken);

            var result = await _userManager.ConfirmEmailAsync(user,encodeToken);
            if (result.Succeeded)
            {
                return Ok();
            }
            else
            {
                return BadRequest(result.Errors);
            }
        }

        //[HttpPost]
        //[Route("Login")]
        //public async Task<IActionResult> Login([FromBody] LoginModel model)
        //{
        //    var user = await _userManager.FindByEmailAsync(model.Email);
        //    if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
        //        return Unauthorized(new AuthResponseDto { ErrorMessage = "Invalid Authentication" });
        //    var signingCredentials = _jwtHandler.GetSigningCredentials();
        //    var claims = _jwtHandler.GetClaims(user);
        //    var tokenOptions = _jwtHandler.GenerateTokenOptions(signingCredentials, claims);
        //    var token = new JwtSecurityTokenHandler().WriteToken(tokenOptions);
        //    return Ok(new AuthResponseDto { IsAuthSuccessful = true, Token = token });
        //}
        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login(LoginModel model)
        {
            await CreateRole();
            await CreateAdmin();
            if (model == null)
                return NotFound();
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
                return NotFound();
            if (!user.EmailConfirmed)
            {
                return Unauthorized("Email is not confirmed yet!!");
            }

            var userName = HttpContext.User.Identity.Name;

            var id = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (id != null || userName != null)
            {
                return BadRequest($"user ud:{id} is exist");
            }

            //var email = User.FindFirst(ClaimTypes.Email)?.Value;
            //if (email != null)
            //{
            //    return BadRequest("user .. logged");
            //}

            var result = await _signInManager.PasswordSignInAsync(user,
                model.Password,
                model.RememberMe,
                true);
            if (result.Succeeded)
            {
                if (await _roleManager.RoleExistsAsync("Admin"))
                {
                    if (await _userManager.IsInRoleAsync(user, "Admin"))
                    {
                        await _userManager.AddToRoleAsync(user, "Admin");

                    }
                    else if (!await _userManager.IsInRoleAsync(user, "Admin"))
                    {
                        await _userManager.AddToRoleAsync(user, "User");
                    }

                }
                var roleName = await GetRoleNameByUserId(user.Id);
                if (roleName != null)
                    AddCookies(user.UserName, roleName, user.Id, model.RememberMe, user.Email);
                return Ok();
            }
            else if (result.IsLockedOut)
            {
                return Unauthorized("User Account Is Locked");
            }
            return StatusCode(StatusCodes.Status204NoContent);
        }



        private async Task<string> GetRoleNameByUserId(string userId)
            {
            var userRole = await _db.UserRoles.FirstOrDefaultAsync(usRo => usRo.UserId == userId);
            if (userRole != null)
            {
                return await _db.Roles.Where(x => x.Id == userRole.RoleId).Select(x => x.Name).FirstOrDefaultAsync();
            }
            return null;
            }

    

        private async Task CreateAdmin()
        {
            var admin = await _userManager.FindByNameAsync("Admin");
            if (admin == null)
            {
                var user = new ApplicationUser
                {
                    Email = "admin@admin.com",
                    UserName = "Admin",
                    EmailConfirmed = true,
                };
                var result=await _userManager.CreateAsync(user, "123#Aa");
                if (result.Succeeded)
                {
                    if(await _roleManager.RoleExistsAsync("Admin")) 
                        await _userManager.AddToRoleAsync(user, "Admin");
                    
                }
            }
        }

        private async Task CreateRole()
        {
            if (_roleManager.Roles.Count() < 1)
            {
                var role = new ApplicationRole
                {
                    Name = "Admin",
                };
                await _roleManager.CreateAsync(role);

                 role = new ApplicationRole
                {
                    Name = "User",
                };
                await _roleManager.CreateAsync(role);
            }    
        }

        [HttpPost]
        private  async void AddCookies(
            string username,
            string role,
            string userId,
            bool remember,
            string email)
        {
            var claim = new List<Claim>
            {
                new Claim(ClaimTypes.Name,username),
                new Claim(ClaimTypes.Email,email),
                new Claim(ClaimTypes.NameIdentifier,userId),
                new Claim(ClaimTypes.Role,role),
            };
            var claimIdentity = new ClaimsIdentity(claim,CookieAuthenticationDefaults.AuthenticationScheme);
            if (remember)
            {
                var authProperities = new AuthenticationProperties
                {
                    AllowRefresh = true,
                    IsPersistent = remember,
                    ExpiresUtc = DateTime.UtcNow.AddDays(10),
                };
                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(claimIdentity),
                    authProperities);
            }
            else
            {
                var authProperities = new AuthenticationProperties
                {
                    AllowRefresh = true,
                    IsPersistent = remember,
                    ExpiresUtc = DateTime.UtcNow.AddMinutes(30),
                };
                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(claimIdentity),
                    authProperities);
            }
        }

        [AllowAnonymous]
        [HttpGet]
        [Route("Logout")]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return Ok();
        }


        [AllowAnonymous]
        [HttpGet]
        [Route("GetRoleName/{email}")]
        public async Task<string> GetRoleName(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var userRole = await _db.UserRoles.FirstOrDefaultAsync(usRo => usRo.UserId == user.Id);
                if (userRole != null)
                {
                    return await _db.Roles.Where(x => x.Id == userRole.RoleId).Select(x => x.Name).FirstOrDefaultAsync();
                }
            }
            return null;
        }

       [Authorize]
        [HttpGet]
        [Route("CheckUserClaims/{email}&{role}")]
        public IActionResult CheckUserClaims(string email,string role)
        {
            var userEmail = User.FindFirst(ClaimTypes.Email)?.Value;
            var id = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var userRole = User.FindFirst(ClaimTypes.Role)?.Value;
            if (userEmail != null && userRole != null && id != null)
            {
                if (email == userEmail && role == userRole)
                {
                    return StatusCode(StatusCodes.Status200OK);
                }
            }
            return StatusCode(StatusCodes.Status203NonAuthoritative);
        }




        [HttpGet]
        [Route("EmailExists")]
        public async Task<IActionResult> EmailExists(string email)
        {
            var exist = await _db.Users.AnyAsync(x => x.Email == email);
            if (exist)
            {
                return StatusCode(StatusCodes.Status200OK);
            }
            return StatusCode(StatusCodes.Status400BadRequest);
        }

        [HttpGet]
        [Route("UserNameExists")]
        public async Task<IActionResult> UserNameExists(string userName)
        {
            var exist = await _db.Users.AnyAsync(x => x.UserName == userName);
            if (exist)
            {
                return StatusCode(StatusCodes.Status200OK);
            }
            return StatusCode(StatusCodes.Status400BadRequest);
        }


        [HttpGet]
        [Route("ForgetPassword/{email}")]
        public async Task<IActionResult> ForgetPassword(string email)
        {
            if (email == null)
            {
                return NotFound();
            }
            
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return NotFound();
            }

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var encodeToken = Encoding.UTF8.GetBytes(token);
            var newToken = WebEncoders.Base64UrlEncode(encodeToken);
            var confirmLink = $"http://localhost:4200/ConfirmPassword?ID={user.Id}&Token={newToken}";
           // var txt = "please confirm your password agin";
           // var link = "<a href=\"" + confirmLink + "\">Password Reset Confirm</a>";
           // var title = "Password confirm";
          //  if (await SendGridAPI.Execute(user.Email, user.UserName, txt, link, title))
           // {
               return new ObjectResult(new {token=newToken });
          //  }
          //  return StatusCode(StatusCodes.Status400BadRequest);
        }

        [HttpPost]
        [Route("ResetPassword")]
        public async Task<IActionResult> ResetPassword(ResetPasswordModel model)
        {   
             if (ModelState.IsValid)
            {
             
                var user = await _userManager.FindByIdAsync(model.ID);
                if (user == null)
                    return NotFound();

                var newToken = WebEncoders.Base64UrlDecode(model.Token);
                var encodeToken = Encoding.UTF8.GetString(newToken);

                var result = await _userManager.ResetPasswordAsync(user, encodeToken,model.Password);
                if (result.Succeeded)
                {
                    return Ok();
                }
            }
            return BadRequest();
        }
    }
}

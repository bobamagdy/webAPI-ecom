using Ecom_Api.Models;
using Ecom_Api.ModelViews.users;
using Ecom_Api.Repository.Admin;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Ecom_Api.Controllers
{
    [Route("[controller]")]
    [ApiController]
    //[Authorize(Roles = "Admin")]

    public class AdminController : ControllerBase
    {
        private readonly IAdminRepository _repo;

        public AdminController(IAdminRepository repo)
        {
            _repo = repo;
        }


        [HttpGet]
        [Route("GetAllUsers")]
        public async Task<IEnumerable<ApplicationUser>> GetAllUsers()
        {
            var users = await _repo.GetUsers();
            if (users == null)
            {
                return null;
            }
            return users;
        }

        [HttpPost]
        [Route("AddNewUser")]
        public async Task<IActionResult> AddNewUser(AddUserModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _repo.AddUser(model);
                if (user != null)
                {
                    return Ok();
                }

            }
            return BadRequest();
        }


        [HttpGet]
        [Route("GetUserData/{id}")]
        public async Task<ActionResult<ApplicationUser>> GetUserData(string id)
        {
            if (id==null)
            {
                return NotFound();
            }
            var user = await _repo.GetUserDataAsync(id);
            if (user != null)
            {
                return user;
            }
            return BadRequest();
        }



        [HttpPut]
        [Route("EdituserData")]
        public async Task<ActionResult<ApplicationUser>> EdituserData(EditUserModel model)
        {
            if (!ModelState.IsValid)    
            {
                return BadRequest();
            }
            var user = await _repo.EditUserAsync(model);
            if (user != null)
            {
                return user;
            }
            return BadRequest();
        }

        [HttpGet]
        [Route("GetUserRole")]
        public async Task<IEnumerable<UserRolesModel>> GetUserRole()
        {
            var userRole = await _repo.GetUserRoleAsync();
            if (userRole == null)
            {
                return null;
            }
            return userRole;
        }
    }
}

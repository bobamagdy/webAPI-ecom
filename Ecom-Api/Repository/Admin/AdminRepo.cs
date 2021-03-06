using Ecom_Api.Models;
using Ecom_Api.ModelViews.users;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Ecom_Api.Repository.Admin
{
    public class AdminRepo : IAdminRepository
    {
        private readonly ApplicationDb _db;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<ApplicationRole> _roleManager;

        public AdminRepo(ApplicationDb db, UserManager<ApplicationUser> userManager,RoleManager<ApplicationRole>roleManager)
        {
            _db = db;
            _userManager = userManager;
            _roleManager = roleManager;
        }

        public async Task<ApplicationUser> AddUser(AddUserModel model)
        {
            if (model == null)
            {
                return null;
            }
            var user = new ApplicationUser
            {
                UserName = model.UserName,
                Email = model.Email,
                PhoneNumber = model.PhoneNumber,
                EmailConfirmed = model.EmailConfirmed,
                Country = model.Country,
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                if (await _roleManager.RoleExistsAsync("User"))
                {
                    if (!await _userManager.IsInRoleAsync(user, "User")&&!await _userManager.IsInRoleAsync(user,"Admin"))
                    {
                        await _userManager.AddToRoleAsync(user, "User");
                    }
                }
                return user;
            }
            return null;
        }

        public async Task<ApplicationUser> EditUserAsync(EditUserModel model)
        {
            if (model == null)
            {
                return null;
            }
            var user = await _db.Users.FirstOrDefaultAsync(x => x.Id == model.Id);
            if (user == null)
            {
                return null;
            }

            if (model.Password != user.PasswordHash)
            {
                var result = await _userManager.RemovePasswordAsync(user);
                if (result.Succeeded)
                {
                    await _userManager.AddPasswordAsync(user, model.Password);
                }
            }
            _db.Users.Attach(user);
            user.Email = model.Email;
            user.UserName = model.UserName;
            user.EmailConfirmed = model.EmailConfirmed;
            user.PhoneNumber = model.PhoneNumber;
            user.Country = model.Country;


            _db.Entry(user).Property(x => x.Email).IsModified = true;
            _db.Entry(user).Property(x => x.UserName).IsModified = true;
            _db.Entry(user).Property(x => x.PhoneNumber).IsModified = true;
            _db.Entry(user).Property(x => x.EmailConfirmed).IsModified = true;
            _db.Entry(user).Property(x => x.Country).IsModified = true;
            await _db.SaveChangesAsync();
            return user;
        }

        public async Task<ApplicationUser> GetUserDataAsync(string id)
        {
            if (id == null)
            {
                return null;
            }
            var user = await _db.Users.FirstOrDefaultAsync(x => x.Id == id);
            if (user == null)
            {
                return null;
            }
            return user;
        }

        public async Task<IEnumerable<UserRolesModel>> GetUserRoleAsync()
        {
            var query = await (
                    from userRole in _db.UserRoles
                    join users in _db.Users
                    on userRole.UserId equals users.Id
                    join roles in _db.Roles
                    on userRole.RoleId equals roles.Id
                    select new
                    {
                        userRole.UserId,
                        users.UserName,
                        userRole.RoleId,
                        roles.Name
                    }
                ).ToListAsync();
            List<UserRolesModel> userRolesModels = new List<UserRolesModel>();
           
            if (query.Count > 0)
            {
                for(int i = 0; i < query.Count; i++)
                {
                    var model = new UserRolesModel
                    {
                        UserId = query[i].UserId,
                        UserName = query[i].UserName,
                        RoleId = query[i].RoleId,
                        RoleName = query[i].Name
                    };
                    userRolesModels.Add(model);
                }
            }
            return userRolesModels;
        }

        public async Task<IEnumerable<ApplicationUser>> GetUsers()
        {
            return await _db.Users.ToListAsync();
        }
    }
}

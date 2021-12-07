using Ecom_Api.Models;
using Ecom_Api.ModelViews.users;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Ecom_Api.Repository.Admin
{
    public interface IAdminRepository
    {
        Task<IEnumerable<ApplicationUser>> GetUsers();

        Task<ApplicationUser> AddUser(AddUserModel model);

        Task<ApplicationUser> GetUserDataAsync(string id);

        Task<ApplicationUser> EditUserAsync(EditUserModel model);

        Task<IEnumerable<UserRolesModel>> GetUserRoleAsync();


    }
}

using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Ecom_Api.Models
{
    public class ResetPasswordModel
    {
        [Required]
        public string ID { get; set; }

        [Required]
        public string Token { get; set; }

        [Required]
        public string Password { get; set; }
    }
}

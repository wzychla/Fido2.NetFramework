using System.ComponentModel.DataAnnotations;

namespace Fido2.NetFramework.Demo.Models.Account
{
    public class CreateModel
    {
        [Required]
        public string UserName { get; set; }

        [Required]
        public string Password { get; set; }
    }
}

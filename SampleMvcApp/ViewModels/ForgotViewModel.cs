using System.ComponentModel.DataAnnotations;

namespace SampleMvcApp.ViewModels
{
    public class ForgotViewModel
    {
        [Required]
        [EmailAddress]
        [Display(Name = "Email Address")]
        public string EmailAddress { get; set; }
    }
}
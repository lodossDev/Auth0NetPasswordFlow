using System.ComponentModel.DataAnnotations;

namespace SampleMvcApp.ViewModels
{
    public class ResetViewModel
    {
        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string NewPassword1 { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Confirm Password")]
        public string NewPassword2 { get; set; }
    }
}
using BililiveRecorder.Core.Api.Model;

namespace BililiveRecorder.Web.Models.Rest
{
    public class CookieTesterResponse
    {
        public bool IsLogin { get; set; }
        public string Message { get; set; } = string.Empty;
        public CookieTesterInfo? Data { get; set; }
    }
}

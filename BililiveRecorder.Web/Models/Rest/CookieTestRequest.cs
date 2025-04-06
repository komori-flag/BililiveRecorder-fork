namespace BililiveRecorder.Web.Models.Rest
{
    public class CookieTestRequest
    {
        public string Cookie { get; set; } = string.Empty;
    }

    public class CookieTestResponse
    {
        public bool IsLogin { get; set; }
        public string Message { get; set; } = string.Empty;
    }
}

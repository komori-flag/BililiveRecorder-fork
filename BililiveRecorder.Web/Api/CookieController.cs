using System.Threading.Tasks;
using BililiveRecorder.Core.Api;
using BililiveRecorder.Web.Models.Rest;
using Microsoft.AspNetCore.Mvc;

namespace BililiveRecorder.Web.Api
{
    [ApiController, Route("api/[controller]", Name = "[controller] [action]")]
    public sealed class CookieController : ControllerBase
    {
        private readonly ICookieTester? httpApiClient;

        public CookieController(ICookieTester? httpApiClient)
        {
            this.httpApiClient = httpApiClient;
        }

        /// <summary>
        /// 测试 Cookie 是否有效
        /// </summary>
        /// <param name="request">包含要测试的 Cookie 的文本</param>
        /// <returns>Cookie 测试结果</returns>
        [HttpPost("test")]
        public async Task<ActionResult<CookieTestResponse>> TestCookieAsync([FromBody] CookieTestRequest request)
        {
            bool isLogin;
            string message;

            var cookie = request.Cookie;

            if (this.httpApiClient is null)
                (isLogin, message) = (false, "No Http Client Available");
            else
                (isLogin, message) = await this.httpApiClient.TestCookieAsync(cookie);

            return new CookieTestResponse
            {
                IsLogin = isLogin,
                Message = message
            };
        }
    }
}

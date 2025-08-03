using System;
using System.Threading.Tasks;
using BililiveRecorder.Core.Api;
using BililiveRecorder.Core.Api.Model;
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
        /// 测试配置中的 Cookie 是否有效
        /// </summary>
        /// <returns>Cookie 测试结果</returns>
        [HttpGet("test")]
        public async Task<ActionResult<CookieTesterResponse>> TestCookieAsync()
        {
            bool isLogin;
            string message;
            CookieTesterInfo? data;

            try
            {
                if (this.httpApiClient is null)
                    (isLogin, message, data) = (false, "No Http Client Available", null);
                else
                    (isLogin, message, data) = await this.httpApiClient.TestCookieAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                (isLogin, message, data) = (false, ex.ToString(), null);
            }

            return new CookieTesterResponse
            {
                IsLogin = isLogin,
                Message = message,
                Data = data,
            };
        }
    }
}

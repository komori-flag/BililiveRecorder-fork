using System.Net.Http;
using System.Threading.Tasks;
using BililiveRecorder.Core.Api.Model;

namespace BililiveRecorder.Core.Api
{
    public interface ICookieTester
    {
        Task<(bool, string, CookieTesterInfo)> TestCookieAsync();
    }
}

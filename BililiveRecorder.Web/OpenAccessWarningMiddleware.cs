using System;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Net.Http.Headers;

namespace BililiveRecorder.Web
{
    public class OpenAccessWarningMiddleware
    {
        private readonly RequestDelegate next;

        public OpenAccessWarningMiddleware(RequestDelegate next)
        {
            this.next = next ?? throw new ArgumentNullException(nameof(next));
        }

        public Task InvokeAsync(HttpContext context)
        {
            if (context.RequestServices.GetService<BasicAuthCredential>() is not null)
            {
                // 启用了身份验证，不需要警告
                return this.next(context);
            }

            if (sourceIpNotLan(context) || haveReverseProxyHeaders(context) || haveCustomHostValue(context))
            {
                context.Response.StatusCode = 412;
                var accept = context.Request.Headers[HeaderNames.Accept].ToString();
                if (accept.Contains("text/html"))
                {
                    context.Response.ContentType = "text/html; charset=utf-8";
                    return context.Response.WriteAsync("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Access Denied</title></head>" +
                    "<body><h1>Access Denied</h1><p>Open access from the internet detected. Please enable basic authentication by setting the environment variables \"BREC_HTTP_BASIC_USER\" and \"BREC_HTTP_BASIC_PASS\", " +
                    "or disable this warning by setting the environment variable \"BREC_HTTP_OPEN_ACCESS\".</p>" +
                    "<p>检测到非局域网无密码访问。请设置使用环境变量 \"BREC_HTTP_BASIC_USER\" 和 \"BREC_HTTP_BASIC_PASS\" 设置用户名密码，" +
                    "或如果你已经通过其他方法实现了访问控制（如只在内网开放）可以通过设置环境变量 \"BREC_HTTP_OPEN_ACCESS\" 为任意值来禁用此警告。暴露在互联网上无密码的录播姬存在安全风险。</p>" +
                    "<hr><p>录播姬 BililiveRecorder " + GitVersionInformation.FullSemVer + "</p></body></html>\n");
                }
                else
                {
                    context.Response.ContentType = "text/plain; charset=utf-8";
                    return context.Response.WriteAsync("Access Denied.\nOpen access from the internet detected. Please enable " +
                    "basic authentication by setting the environment variables \"BREC_HTTP_BASIC_USER\" and \"BREC_HTTP_BASIC_PASS\", " +
                    "or disable this warning by setting the environment variable \"BREC_HTTP_OPEN_ACCESS\".\n" +
                    "检测到非局域网无密码访问。请设置使用环境变量 \"BREC_HTTP_BASIC_USER\" 和 \"BREC_HTTP_BASIC_PASS\" 设置用户名密码，" +
                    "或如果你已经通过其他方法实现了访问控制（如只在内网开放）可以通过设置环境变量 \"BREC_HTTP_OPEN_ACCESS\" 为任意值来禁用此警告。暴露在互联网上无密码的录播姬存在安全风险。\n" +
                    "录播姬 BililiveRecorder " + GitVersionInformation.FullSemVer + "\n");
                }
            }
            else
            {
                return this.next(context);
            }
        }

        private static bool sourceIpNotLan(HttpContext context)
        {
            var ip = context.Connection.RemoteIpAddress;
            if (ip is null) return true;
            return
                !isLocalIpv4Address(ip) && // LAN IPV4 and loopback IPV4
                !isLoopbackAddress(ip) && // loopback IPV4/IPV6
                !ip.IsIPv6LinkLocal && // link-local IPV6
                !ip.IsIPv6UniqueLocal; // unique-local IPV6
        }

        private static bool isLocalIpv4Address(IPAddress ip)
        {
            if (ip.IsIPv4MappedToIPv6)
                ip = ip.MapToIPv4();

            if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                return false;

            var bytes = ip.GetAddressBytes();
            if (bytes.Length != 4)
                return false;
            switch (bytes[0])
            {
                case 10: // 10.0.0.0/8
                    return true;
                case 127: // 127.0.0.0/8
                    return true;
                case 172: // 172.16.0.0/12
                    return bytes[1] >= 16 && bytes[1] <= 31;
                case 192: // 192.168.0.0/16
                    return bytes[1] == 168;
                default:
                    return false;
            }
        }

        private static bool isLoopbackAddress(IPAddress ip)
        {
            if (ip.AddressFamily is System.Net.Sockets.AddressFamily.InterNetworkV6 ||
                ip.AddressFamily is System.Net.Sockets.AddressFamily.InterNetwork)
                return IPAddress.IsLoopback(ip);

            return false;
        }

        private static bool haveReverseProxyHeaders(HttpContext context)
        {
            return
                context.Request.Headers.ContainsKey("X-Real-IP") ||
                context.Request.Headers.ContainsKey("X-Forwarded-For") ||
                context.Request.Headers.ContainsKey("X-Forwarded-Host") ||
                context.Request.Headers.ContainsKey("X-Forwarded-Proto") ||
                context.Request.Headers.ContainsKey("Via");
        }

        private static bool haveCustomHostValue(HttpContext context)
        {
            // check if the host header is set to a custom value such as a domain name
            if (IPAddress.TryParse(context.Request.Host.Host, out var ip))
            {
                var localIP = context.Connection.LocalIpAddress;
                if (localIP is not null && localIP.IsIPv4MappedToIPv6)
                    localIP = localIP.MapToIPv4();

                /*
                 * 需要判断访问者的 Host 是否为 LAN IP 或 保留 IP
                 * 1. 判断访问者传入的 Host IP 地址与访问者的 IP 地址是否相同
                 * 2. 判断访问者传入的 Host IP 地址是否为 LAN IP 或 保留 IP
                 * 3. 判断访问者的 IP 地址是否为 LAN IP 或 保留 IP
                 */
                // 访问者传入的 Host 和 IP 为 IPV6
                if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 &&
                    localIP?.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                {
                    // 判断传入的 Host IP 地址是否为本地环回地址
                    if (isLoopbackAddress(ip) && isLoopbackAddress(localIP))
                        return !ip.Equals(localIP);

                    return
                        !ip.Equals(localIP) ||
                        !ip.IsIPv6UniqueLocal ||
                        !ip.IsIPv6UniqueLocal;
                }

                return
                    !ip.Equals(localIP) ||
                    !isLocalIpv4Address(ip) ||
                    !isLocalIpv4Address(localIP);
            }

            // check if the host header is set to "localhost" IP address
            if (context.Request.Host.Host.Equals("localhost"))
            {
                /*
                 * 判断是否为本机访问本机环回地址
                 * 1. 判断访问者的 IP 地址与本机 IP 地址是否相同
                 * 2. 判断访问者的 IP 地址是否为本机环回地址
                 * 3. 判断本机的 IP 地址是否为本机环回地址
                */
                return
                    context.Connection.RemoteIpAddress is null ||
                    context.Connection.LocalIpAddress is null ||
                    !context.Connection.RemoteIpAddress.Equals(context.Connection.LocalIpAddress) ||
                    !isLoopbackAddress(context.Connection.RemoteIpAddress) ||
                    !isLoopbackAddress(context.Connection.LocalIpAddress);
            }

            // the host header is not an IP address
            return true;
        }
    }
}

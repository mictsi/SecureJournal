using System.Net;
using Microsoft.AspNetCore.HttpOverrides;

namespace SecureJournal.Web.Infrastructure;

internal static class TrustedProxyConfiguration
{
    public static void Apply(ForwardedHeadersOptions options, IConfiguration configuration)
    {
        options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;

        // Keep trust explicit even when a hosting environment enables forwarded
        // headers globally. The framework's loopback defaults remain trusted.
        options.KnownProxies.Clear();
        options.KnownIPNetworks.Clear();
        options.KnownProxies.Add(IPAddress.IPv6Loopback);
        options.KnownIPNetworks.Add(System.Net.IPNetwork.Parse("127.0.0.0/8"));

        foreach (var proxy in configuration.GetSection("ForwardedHeaders:KnownProxies").GetChildren())
        {
            if (!IPAddress.TryParse(proxy.Value, out var address))
            {
                throw new InvalidOperationException($"{proxy.Path} must contain a valid proxy IP address.");
            }

            options.KnownProxies.Add(address);
        }

        foreach (var network in configuration.GetSection("ForwardedHeaders:KnownNetworks").GetChildren())
        {
            if (!System.Net.IPNetwork.TryParse(network.Value, out var range))
            {
                throw new InvalidOperationException($"{network.Path} must contain a valid CIDR range.");
            }

            options.KnownIPNetworks.Add(range);
        }
    }
}

# cloudflare-ddns

Yet another ddns client over cloudflare api written by rust.

# How to use?

You should provide four arguments.

```
--token <TOKEN>
--zone <ZONE>
--domain <DOMAIN>
--ipserver <IPSERVER>
```

- `token`: Your cloudflare api token
- `zone`:  The zone which your domain in
- `domain`: Your domain
- `ipserver`: A server address which should response like `{ "ip": "xxx.xxx.xxx.xxx" }`.

# How it works?

The program will query ipserver and domain's ip at start. Then

1. If the ipserver returns ip is equal with domain's ip, do nothing.
2. If not, try update with cloudflare api.
3. Wait utill domain's ttl expired.
4. Return 1.

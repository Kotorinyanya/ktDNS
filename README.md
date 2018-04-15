# ktDNS

ktDNS stands for kotori-DNS server.

This is a simple implementation of DNS servers, only [itsukakotori.moe](itsukakotori.moe) and [google.com](google.com) is supported, and I won't add any other DNS records in the future.

## usage

run `ktDNS.py` at root privilege for this need to bind on 53 port

```
sudo python3 ktDNS.py
```

Then use dig command to see if this take effect (specify the DNS server to 127.0.0.1)

```
dig itsukakotori.moe @127.0.0.1
```

## TODO

Execption handling

Get rid of global variable `zone`


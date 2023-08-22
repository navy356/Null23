# Web
## Debugger
![html comments](https://github.com/navy356/Null23/blob/main/debugger/debugger3.png?raw=true)
As seen by in the html comments, we can view the source. 
![html comments](https://github.com/navy356/Null23/blob/main/debugger/debugger1png.png?raw=true)

![source code](https://github.com/navy356/Null23/blob/main/debugger/debugger2.png?raw=true)

Clearly our goal is to set ``$is_admin`` to true to include ``flag.php``. Looking closely we can see the following code:
```
$debug_info = get_debug_info(extract($_GET['filters']));
```
As per the [manual](https://www.php.net/manual/en/function.extract.php) for the function ``extract`` it can ``Import variables into the current symbol table from an array``. So all we have to do is pass a key/value pair of ``is_admin/1`` through filters variable to include ``flag.php``.

![flag](https://github.com/navy356/Null23/blob/main/debugger/debugger.png?raw=true)
 
## TYPical Boss
![error](https://github.com/navy356/Null23/blob/main/TypicalBoss/boss5.png?raw=true)
We do not quite get the same luxury in this one. Seeing a login page and the name of this task, it was quite clearly some type of php type juggling task. So I tried to induce an error to get more information for starters.
![error](https://github.com/navy356/Null23/blob/main/TypicalBoss/boss.png?raw=true)

There we go. At this point, though we already know what to do I will still list out my thought process. As in [this article](https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf), PHP's strange loose comparision may make a string like ``0exxxxxx`` where x is some number get converted into ``int(0)`` under certain conditions and pass checks unexpectedly. In this case, we are not aware of the exact condition to bypass but welcome to web. I went to look for a sha1 string that turns into a hash which satisfies the above conditions. I could script it, but it's probably already online somewhere so no need to bother. [This link](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Type%20Juggling/README.md) gives us a nice one.
![sha1](https://github.com/navy356/Null23/blob/main/TypicalBoss/boss4.png?raw=true)

We can just enter that and password. After a failed ``test/10932435112`` combo, I tried ``admin/10932435112`` and there we go.

![sha1](https://github.com/navy356/Null23/blob/main/TypicalBoss/boss2.png?raw=true)

![sha1](https://github.com/navy356/Null23/blob/main/TypicalBoss/boss3.png?raw=true)

## IPfilter
![description](https://github.com/navy356/Null23/blob/main/IPfilter/ip1.png?raw=true)
Ah, this one. Trying it out much longer than I'd like to admit, I had mixed feelings with the announcement.
![announcement](https://github.com/navy356/Null23/blob/main/IPfilter/ip.png?raw=true)
But oh well, let's get to it. Once again, we are free to view the source.
![html comments](https://github.com/navy356/Null23/blob/main/IPfilter/ip2.png?raw=true)
![source code](https://github.com/navy356/Null23/blob/main/IPfilter/ip3.png?raw=true)

Going by this line 
```
if($ip == $backend) {  
// Do not allow the backend with our secrets ;-)  
return true;  
}
```
Our goal is to fetch the backend somehow. We first run the actions with the ``debug_filter`` to get the relevant data.
![debug](https://github.com/navy356/Null23/blob/main/IPfilter/ip4.png?raw=true)

So we can look up any ip within the subnet. It's not useful if it is not ``192.168.112.3`` however. A simple fix is trying ``192.168.112.03``. 
Let us focus on this:
```
if(inet_pton($ip) < (int) inet_pton($subnet)) {  
// Do not go below the subnet!  
return true;  
}
```
The ``(int)`` was added after the announcement. Here is why we kept failing this check before they fixed it:
![issue](https://github.com/navy356/Null23/blob/main/IPfilter/ip6.png?raw=true)

``inet_pton`` simply returns a ``bool(false)`` for what it considers an invalid ipv4 address. The [comparision](https://www.php.net/manual/en/types.comparisons.php) between a bool ``false`` and what we can consider a ``"1""`` returns true for less than. PHP is weird indeed. The ``(int)`` tyepcast fixes this and we can happily get our flag now.
![flag](https://github.com/navy356/Null23/blob/main/IPfilter/ip5.png?raw=true)

## Colorful
![desc](https://github.com/navy356/Null23/blob/main/Colorful/color1.png?raw=true)
 Right off the bat, we are greeted with some flask source code. 
![source](https://github.com/navy356/Null23/blob/main/Colorful/color.png?raw=true)

From this section:
```
if session['admin'] == '1':
        return open("FLAG").read()
```
our goal is clearly to set ``session['admin']`` to ``1``.

The following code in index fetched the session:
```
session = app.session_handler.get(request,None)
```
which in turn calls these three functions:
```
def get(self, r, p):
        return self.get_session(r)

def get_session(self, r):
        session = r.cookies.get("session", None)
        if not session:
            session = self.new_session(r)
        return self.parse(self._d(session))

def parse(self, c):
        d = {}
        if c is None:
            return d
        for p in c.split("&"):
            try:
                k,v = p.split("=")
                if not k in d:
                    d[k]=v
            except:
                pass
        return d
```
We will come back to this in a bit. First let's discuss the color change route.
It calls:
```
app.session_handler.set(request, response,"color",color)
```
which in turn calls:
```
def set(self, r,p, key=None, val=None):
        session = self.get_session(r)
        if key and val:
            session[key] = val
        session = self.set_session(r, session)
        p.set_cookie("session", session, path='/')
        return session
def set_session(self, r, s):
        c = ""
        for k in sorted(s.keys()):
            c+= f"{k}={s[k]}&"
        return self._c(c)
def get_session(self, r):
        session = r.cookies.get("session", None)
        if not session:
            session = self.new_session(r)
        return self.parse(self._d(session))
```

The first thought that comes to mind is we can simply set ``color`` to ``ff85c0&admin=1`` but according to the ``parse`` function if admin is already set (as in default session cookie) that will not work.
However, the ``set`` function happens to call ``get_session`` which returns the given session or a new one and then parses it. So if we enter gibberish like ``session=1``, ``get_session`` returns an empty session. We can then set color to ``ff85c0&admin=1`` and next time index calls ``get_session``, the parse function return ``admin=1`` and we get the flag.

![source](https://github.com/navy356/Null23/blob/main/Colorful/color2.png?raw=true)

![source](https://github.com/navy356/Null23/blob/main/Colorful/color3.png?raw=true)

## Magic Cars
![desc](https://github.com/navy356/Null23/blob/main/MagicCars/cars.png?raw=true)

The source code is given. I have attached an image of the relevant part.

![source](https://github.com/navy356/Null23/blob/main/MagicCars/cars1.png?raw=true)

Our goal is probably RCE through a php file upload. So we have two things to bypass the extension and the mime type check.

The mime type check can be easily bypassed by adding a ``GIF87a`` to the beginning of the file, which happens to be the ``magic number`` for ``image/gif``.

As for the extension, we can see that we first get extension, shorten string using 
```
$target_dir = strtok($target_dir,chr(0));
```
which removes any characters after null byte and the move the file to the proper location.

So we can just upload a file named ``shell.php%00.gif``. While the extension will be detected as ``.gif``, it wiil be shortened and uploaded as ``.php``. Then we can simply go to ``/images/shell.php`` and get our flag.

![source](https://github.com/navy356/Null23/blob/main/MagicCars/cars2.png?raw=true)

![source](https://github.com/navy356/Null23/blob/main/MagicCars/cars3.png?raw=true)

## LoginBytePass
![source](https://github.com/navy356/Null23/blob/main/LoginBytePass/login4.png?raw=true)
We can check the source code.
![source](https://github.com/navy356/Null23/blob/main/LoginBytePass/login1.png?raw=true)
![source](https://github.com/navy356/Null23/blob/main/LoginBytePass/login.png?raw=true)

As we can see:
```
$password = md5(md5($password, true), true);  
$res = mysqli_query($db, "SELECT * FROM users WHERE username = '$username' AND password = '$password'");
```
our goal is sql injection with raw md5 hash.
We just need to find a hash with a small sqli payload as substring. I used ``'='`` because it's short. It works as follows:

![source](https://github.com/navy356/Null23/blob/main/LoginBytePass/login5.png?raw=true)

Basically it turns the payload into ``password='a'='cccc'`` which evaluates to ``password=false`` which returns rows where password is a non-zero value.

I wrote a simple php script to do the bruteforcing for me.
```
<?php
	$pattern = "/'='/i";
	for ($x = 0; $x <= 2000000*10; $x+=10) {
		$test = md5(md5(strval($x), true), true);
		if (preg_match($pattern, $test)){
			echo  $x;
			echo PHP_EOL;
			echo  $test;
			break;
		}
	}
?>
```
In a few seconds, we have our payload ready to go.

![source](https://github.com/navy356/Null23/blob/main/LoginBytePass/login2.png?raw=true)

We can just enter the value and get our flag.

![source](https://github.com/navy356/Null23/blob/main/LoginBytePass/login3.png?raw=true)

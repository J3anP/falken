# Falken

Un escáner de puertos rápido y minimalista escrito en Go.

## Características

- Usa goroutines + worker pool, así que escanea miles de puertos sin que tu CPU sufra.
- Rate limiting integrado, por si no quieres que el firewall del objetivo se ponga nervioso.
- Detección de servicio opcional, para saber qué corre detrás de cada puerto.
- Exporta resultados en JSON, listo para meter en otro script o reporte.

## Instalación

Con Go instalado (1.21+):

```bash
go install github.com/J3anP/falken@latest
```

O clonando el repo y compilando vos mismo:

```bash
git clone https://github.com/J3anP/falken.git
cd falken
go build -o falken
```

## Uso

```bash
./falken -t scanme.nmap.org -p top-100 -w 150 -sV -o resultado.json
```

Salida esperada:

```
[*] Objetivo:   scanme.nmap.org
[*] Puertos:    100 (top-100)
[*] Workers:    150

[*] Verificando si el host está activo...
[*] Progreso: 100/100 puertos (100.0%)

[+] 22/tcp abierto — SSH-2.0-OpenSSH_8.2p1 Ubuntu
[+] 80/tcp abierto — HTTP/1.1 200 OK
[+] 443/tcp abierto

----------------------------------------------
  RESUMEN DEL ESCANEO
----------------------------------------------
  Objetivo:         scanme.nmap.org
  Puertos abiertos: 3 / 100
  Duración:         3.42s
----------------------------------------------

[+] Resultados exportados a resultado.json
```

Opciones disponibles:

```
  -t, --target string     IP o dominio objetivo (requerido)
  -p, --ports string      "80,443" / "1-1024" / "top-100" (default "1-1024")
  -w, --workers int       Goroutines concurrentes (default 100)
  -o, --output string     Exportar resultado a JSON
      --rate int          Límite de conexiones por segundo (0 = sin límite)
      --timeout int       Timeout de conexión en ms (default 800)
  -sV                     Detección de servicio/banner
  -sU                     Modo UDP en vez de TCP
  -Pn                     Saltar host discovery
```

## Aviso

Esta herramienta es solo para uso en sistemas donde tengas autorización explícita.
El uso no autorizado contra redes de terceros es ilegal. El autor no se hace
responsable del mal uso de esta herramienta.

## Licencia

MIT. Usalo, modificalo, lo que quieras - solo no me culpes si algo explota.

# Web XPL Bot (Discord)

Bot para reconhecimento ativo e passivo desenvolvido para o Check Point 1.

## Comandos Implementados:
- /nmap <host>: Varredura rapida de portas via Nmap real (-F -Pn).
- /ipinfo <IP>: Consulta geolocalizacao e ASN via ipinfo.io.
- /crt <dominio>: Descoberta passiva de subdominios via crt.sh e Passive DNS.
- /gau <dominio>: Coleta passiva de URLs via AlienVault OTX e Wayback Machine.
- /whois <dominio>: Consulta cadastral via protocolo seguro RDAP (porta 443).
- /dns <dominio>: Consulta de registros A, MX, NS e TXT.

## Como Executar Localmente:
1. Instale as dependencias: pip install -r requirements.txt
2. Configure suas variaveis no arquivo .env
3. Inicie o bot: python bot.py

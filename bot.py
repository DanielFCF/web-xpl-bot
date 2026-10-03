import os
import re
import asyncio
import aiohttp
import dns.resolver
import discord
from discord import app_commands
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("DISCORD_BOT_TOKEN")
GUILD_ID = os.getenv("DISCORD_GUILD_ID")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")

# Headers de navegador para evitar bloqueios em APIs públicas
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

DOMAIN_REGEX = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
IP_REGEX = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")

def is_valid_domain(domain: str) -> bool:
    return bool(DOMAIN_REGEX.match(domain.strip()))

def is_valid_ip(ip_addr: str) -> bool:
    return bool(IP_REGEX.match(ip_addr.strip()))

class ReconBot(discord.Client):
    def __init__(self):
        super().__init__(intents=discord.Intents.default())
        self.tree = app_commands.CommandTree(self)

    async def setup_hook(self):
        if GUILD_ID:
            guild_obj = discord.Object(id=int(GUILD_ID))
            self.tree.copy_global_to(guild=guild_obj)
            await self.tree.sync(guild=guild_obj)
            print(f"[*] Comandos sincronizados para a Guild: {GUILD_ID}")
        else:
            await self.tree.sync()
            print("[*] Comandos sincronizados globalmente.")

bot = ReconBot()

@bot.event
async def on_ready():
    print(f"[+] Bot online e conectado como: {bot.user}")

# 1. /ipinfo <IP>
@bot.tree.command(name="ipinfo", description="Consulta geolocalizacao e ASN de um endereco IPv4.")
@app_commands.describe(ip="Endereco IPv4 valido (ex: 8.8.8.8)")
async def cmd_ipinfo(interaction: discord.Interaction, ip: str):
    await interaction.response.defer()
    target_ip = ip.strip()

    if not is_valid_ip(target_ip):
        await interaction.followup.send("❌ Endereco IPv4 invalido.")
        return

    url = f"https://ipinfo.io/{target_ip}/json"
    params = {"token": IPINFO_TOKEN} if IPINFO_TOKEN else {}

    try:
        async with aiohttp.ClientSession(headers=HEADERS) as session:
            async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                if resp.status != 200:
                    await interaction.followup.send(f"⚠️ Erro ao consultar ipinfo.io (Status {resp.status}).")
                    return
                data = await resp.json()

        embed = discord.Embed(title=f"🌐 IPInfo: {target_ip}", color=0x3498db)
        embed.add_field(name="Pais / Regiao", value=f"{data.get('country', 'N/A')} - {data.get('region', 'N/A')}", inline=True)
        embed.add_field(name="Cidade", value=data.get("city", "N/A"), inline=True)
        embed.add_field(name="Organizacao / ASN", value=data.get("org", "N/A"), inline=False)
        embed.add_field(name="Coordenadas", value=data.get("loc", "N/A"), inline=True)
        embed.add_field(name="Fuso Horario", value=data.get("timezone", "N/A"), inline=True)
        await interaction.followup.send(embed=embed)
    except Exception as e:
        await interaction.followup.send(f"❌ Falha na consulta: {str(e)}")

# 2. /crt <dominio> (com fallback resiliente para HackerTarget)
@bot.tree.command(name="crt", description="Enumera subdominios via Certificate Transparency ou Passive DNS.")
@app_commands.describe(dominio="Dominio alvo (ex: fiap.com.br)")
async def cmd_crt(interaction: discord.Interaction, dominio: str):
    await interaction.response.defer()
    dom = dominio.strip().lower()

    if not is_valid_domain(dom):
        await interaction.followup.send("❌ Dominio invalido.")
        return

    subdomains = set()
    fonte = "crt.sh"

    # Tentativa 1: crt.sh com timeout de 10s
    try:
        url_crt = f"https://crt.sh/?q={dom}&output=json"
        async with aiohttp.ClientSession(headers=HEADERS) as session:
            async with session.get(url_crt, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for item in data:
                        for n in item.get("name_value", "").split("\n"):
                            n = n.strip().lower()
                            if dom in n and not n.startswith("*"):
                                subdomains.add(n)
    except Exception:
        pass

    # Fallback instantâneo via HackerTarget se crt.sh demorar
    if not subdomains:
        fonte = "HackerTarget (Passive DNS)"
        try:
            url_ht = f"https://api.hackertarget.com/hostsearch/?q={dom}"
            async with aiohttp.ClientSession(headers=HEADERS) as session:
                async with session.get(url_ht, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        for line in text.splitlines():
                            parts = line.split(",")
                            if parts and dom in parts[0]:
                                subdomains.add(parts[0].strip().lower())
        except Exception:
            pass

    if not subdomains:
        await interaction.followup.send(f"ℹ️ Nenhum subdominio encontrado para `{dom}`.")
        return

    sorted_subs = sorted(list(subdomains))[:20]
    resultado = "\n".join(f"• {s}" for s in sorted_subs)
    
    embed = discord.Embed(title=f"📜 Subdominios Encontrados ({fonte}): {dom}", color=0x2ecc71)
    embed.description = f"Total descoberto: {len(subdomains)} (mostrando {len(sorted_subs)}):\n```text\n{resultado}\n```"
    await interaction.followup.send(embed=embed)

# 3. /gau <dominio> (AlienVault OTX + Wayback Machine com User-Agent)
@bot.tree.command(name="gau", description="Coleta passiva de URLs historicas (GetAllURLs).")
@app_commands.describe(dominio="Dominio alvo (ex: fiap.com.br)")
async def cmd_gau(interaction: discord.Interaction, dominio: str):
    await interaction.response.defer()
    dom = dominio.strip().lower()

    if not is_valid_domain(dom):
        await interaction.followup.send("❌ Dominio invalido.")
        return

    urls = set()

    # Fonte 1: AlienVault OTX (Super rapido e estavel)
    try:
        url_otx = f"https://otx.alienvault.com/api/v1/indicators/domain/{dom}/url_list?limit=15"
        async with aiohttp.ClientSession(headers=HEADERS) as session:
            async with session.get(url_otx, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for item in data.get("url_list", []):
                        if "url" in item:
                            urls.add(item["url"])
    except Exception:
        pass

    # Fonte 2: Wayback Machine (Fallback)
    if len(urls) < 5:
        try:
            url_wb = f"https://web.archive.org/cdx/search/cdx?url={dom}/*&output=json&fl=original&collapse=urlkey&limit=15"
            async with aiohttp.ClientSession(headers=HEADERS) as session:
                async with session.get(url_wb, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        rows = await resp.json()
                        for r in rows:
                            if r and r[0] != "original":
                                urls.add(r[0])
        except Exception:
            pass

    if not urls:
        await interaction.followup.send(f"ℹ️ Nenhuma URL historica arquivada encontrada para `{dom}`.")
        return

    amostra = list(urls)[:12]
    resultado = "\n".join(amostra)
    embed = discord.Embed(title=f"📂 Endpoints Coletados (GAU): {dom}", color=0xe67e22)
    embed.description = f"```text\n{resultado}\n```"
    await interaction.followup.send(embed=embed)

# 4. /nmap <host>
@bot.tree.command(name="nmap", description="Executa um scan rapido de portas com o Nmap.")
@app_commands.describe(host="Host ou IP alvo (ex: scanme.nmap.org)")
async def cmd_nmap(interaction: discord.Interaction, host: str):
    await interaction.response.defer()
    target = host.strip()

    if not (is_valid_domain(target) or is_valid_ip(target)):
        await interaction.followup.send("❌ Alvo invalido. Forneca um dominio ou IPv4 valido.")
        return

    try:
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-F", "-Pn", "--open", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=35.0)

        output = stdout.decode("utf-8", errors="ignore")
        if not output:
            output = stderr.decode("utf-8", errors="ignore") or "Sem saida reportada pelo Nmap."

        if len(output) > 1800:
            output = output[:1800] + "\n... [saida truncada]"

        embed = discord.Embed(title=f"🔍 Nmap Scan (-F -Pn): {target}", color=0x9b59b6)
        embed.description = f"```text\n{output}\n```"
        await interaction.followup.send(embed=embed)
    except FileNotFoundError:
        await interaction.followup.send("⚠️ O executavel `nmap` nao foi encontrado no PATH do sistema.")
    except asyncio.TimeoutError:
        await interaction.followup.send("⏳ O scan do Nmap excedeu o tempo limite (35s).")
    except Exception as e:
        await interaction.followup.send(f"❌ Erro ao executar Nmap: {str(e)}")

# 5. /whois <dominio> (Via RDAP HTTP - Porta 443 liberada em qualquer rede)
@bot.tree.command(name="whois", description="Consulta registro WHOIS/RDAP via HTTPS.")
@app_commands.describe(dominio="Dominio alvo (ex: google.com ou fiap.com.br)")
async def cmd_whois(interaction: discord.Interaction, dominio: str):
    await interaction.response.defer()
    dom = dominio.strip().lower()

    if not is_valid_domain(dom):
        await interaction.followup.send("❌ Dominio invalido.")
        return

    url = f"https://rdap.org/domain/{dom}"
    try:
        async with aiohttp.ClientSession(headers=HEADERS) as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status != 200:
                    await interaction.followup.send(f"⚠️ RDAP/WHOIS retornou status {resp.status} para `{dom}`.")
                    return
                data = await resp.json()

        # Extração dos dados do RDAP
        handle = data.get("handle", "N/A")
        
        # Procura registrar nos entities
        registrar = "N/A"
        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                vcard = entity.get("vcardArray", [])
                if len(vcard) > 1:
                    for prop in vcard[1]:
                        if prop[0] == "fn":
                            registrar = prop[3]
                            break

        events = {e.get("eventAction"): e.get("eventDate", "")[:10] for e in data.get("events", [])}
        criado = events.get("registration", "N/A")
        expira = events.get("expiration", "N/A")

        embed = discord.Embed(title=f"👤 WHOIS / RDAP: {dom}", color=0x34495e)
        embed.add_field(name="ID / Handle", value=handle, inline=True)
        embed.add_field(name="Registrar", value=registrar, inline=True)
        embed.add_field(name="Data de Criacao", value=criado, inline=True)
        embed.add_field(name="Data de Expiracao", value=expira, inline=True)
        await interaction.followup.send(embed=embed)
    except Exception as e:
        await interaction.followup.send(f"❌ Falha na consulta WHOIS: {str(e)}")

# 6. /dns <dominio>
@bot.tree.command(name="dns", description="Consulta registros DNS (A, MX, NS, TXT).")
@app_commands.describe(dominio="Dominio alvo (ex: fiap.com.br)")
async def cmd_dns(interaction: discord.Interaction, dominio: str):
    await interaction.response.defer()
    dom = dominio.strip().lower()

    if not is_valid_domain(dom):
        await interaction.followup.send("❌ Dominio invalido.")
        return

    def resolve_dns_sync(d, r_type):
        try:
            res = dns.resolver.resolve(d, r_type)
            return [str(r.to_text()) for r in res][:3]
        except Exception:
            return ["Nenhum registro encontrado"]

    results = {}
    for r_type in ["A", "MX", "NS", "TXT"]:
        results[r_type] = await asyncio.to_thread(resolve_dns_sync, dom, r_type)

    embed = discord.Embed(title=f"📋 Registros DNS: {dom}", color=0x1abc9c)
    for r_type, entries in results.items():
        embed.add_field(name=r_type, value="\n".join(entries), inline=False)

    await interaction.followup.send(embed=embed)

if __name__ == "__main__":
    if not TOKEN:
        raise ValueError("A variavel DISCORD_BOT_TOKEN nao foi definida no .env.")
    bot.run(TOKEN)
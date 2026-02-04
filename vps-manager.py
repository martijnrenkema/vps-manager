#!/usr/bin/env python3
"""
VPS Manager - Interactive Management Tool

Centraal beheer van VPS 212.227.135.150 vanuit lokale Mac terminal.

Usage:
    python vps-manager.py                    # Interactief menu
    python vps-manager.py --status           # Server overview
    python vps-manager.py --sites            # Websites overzicht
    python vps-manager.py --pm2              # PM2 list
    python vps-manager.py --ssl              # SSL certificaten
    python vps-manager.py --services         # Service status
    python vps-manager.py --backup           # Backup status
    python vps-manager.py --deploy SITE      # Deploy specifieke site
    python vps-manager.py --reboot           # Server reboot
    python vps-manager.py --firewall         # Firewall status
    python vps-manager.py --all              # Alles in één overzicht
"""

import subprocess
import sys
import time
import argparse
import os
import re
from datetime import datetime, timedelta

# Configuration
VPS_HOST = "212.227.135.150"
VPS_USER = "martijn"
SSH_ALIAS = "vps"  # Gebruikt ~/.ssh/config alias (met multiplexing)

# Deploy site configuration
SITES = {
    'djmartijn.nl': {
        'local': '/Volumes/martijn/Documenten/Projects/djmartijn-website25/',
        'remote': '/var/www/djmartijn.nl/',
        'type': 'static'
    },
    'blenderdjshow.nl': {
        'local': "/Volumes/martijn/Documenten/Projects/Blender DJ Show website '25/",
        'remote': '/var/www/blenderdjshow.nl/',
        'type': 'static'
    },
    'home.dmmusic.nl': {
        'local_frontend': '/Volumes/martijn/Documenten/Projects/minevents/dist/',
        'remote_frontend': '/var/www/home.dmmusic.nl/web/',
        'local_api': '/Volumes/web/web/api/',
        'remote_api': '/var/www/home.dmmusic.nl/api/',
        'type': 'expo+php'
    },
    'aanvraag.dmmusic.nl': {
        'local': '/Volumes/web/DJ-aanvraag/',
        'remote': '/var/www/aanvraag.dmmusic.nl/',
        'type': 'nextjs',
        'pm2_name': 'dj-aanvraag',
        'exclude': ['node_modules', '.next', '.git']
    }
}

# Known services to check (auto-detected if not found)
DEFAULT_SERVICES = ['nginx', 'php8.3-fpm', 'mariadb', 'fail2ban']

# Colors for output
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    END = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'


def clear_screen():
    """Clear terminal screen"""
    os.system('clear' if os.name != 'nt' else 'cls')


def print_logo():
    """Print ASCII logo"""
    logo = f"""
{Colors.CYAN}{Colors.BOLD}
    ██╗   ██╗██████╗ ███████╗
    ██║   ██║██╔══██╗██╔════╝
    ██║   ██║██████╔╝███████╗
    ╚██╗ ██╔╝██╔═══╝ ╚════██║
     ╚████╔╝ ██║     ███████║
      ╚═══╝  ╚═╝     ╚══════╝
{Colors.END}{Colors.DIM}    Manager v1.0 | {VPS_HOST} | {VPS_USER}@vps{Colors.END}
"""
    print(logo)


def print_menu():
    """Print interactive menu"""
    w = 58
    print(f"""
{Colors.WHITE}{Colors.BOLD}  {'─' * w}
  VPS MANAGER MENU
  {'─' * w}{Colors.END}
{Colors.GREEN}  [1]{Colors.END} 📊 Server Overview     {Colors.DIM}(uptime, CPU, RAM, disk){Colors.END}
{Colors.GREEN}  [2]{Colors.END} 🌐 Websites            {Colors.DIM}(nginx sites + HTTP check){Colors.END}
{Colors.YELLOW}  [3]{Colors.END} ⚙️  PM2 Management      {Colors.DIM}(list, restart, stop, logs){Colors.END}
{Colors.YELLOW}  [4]{Colors.END} 🔒 SSL Certificaten    {Colors.DIM}(verloopdatums per domein){Colors.END}
{Colors.BLUE}  [5]{Colors.END} 🩺 Services            {Colors.DIM}(nginx, php-fpm, mariadb){Colors.END}
{Colors.BLUE}  [6]{Colors.END} 💾 Backup Status       {Colors.DIM}(laatste backup + NAS sync){Colors.END}
{Colors.MAGENTA}  [7]{Colors.END} 🛡️  Firewall & Security {Colors.DIM}(UFW, fail2ban, auth log){Colors.END}
{Colors.CYAN}  [8]{Colors.END} 🚀 Deploy Site         {Colors.DIM}(rsync naar VPS){Colors.END}
{Colors.WHITE}{Colors.BOLD}  {'─' * w}{Colors.END}
{Colors.CYAN}  [U]{Colors.END} 📦 System Updates      {Colors.DIM}(apt upgradable packages){Colors.END}
{Colors.CYAN}  [N]{Colors.END} 📋 Nginx Logs          {Colors.DIM}(error + access logs){Colors.END}
{Colors.CYAN}  [D]{Colors.END} 🗄️  Databases           {Colors.DIM}(MariaDB databases + groottes){Colors.END}
{Colors.CYAN}  [C]{Colors.END} ⏰ Cronjobs            {Colors.DIM}(geplande taken){Colors.END}
{Colors.CYAN}  [S]{Colors.END} 📁 Disk per Site       {Colors.DIM}(ruimtegebruik /var/www){Colors.END}
{Colors.WHITE}{Colors.BOLD}  {'─' * w}{Colors.END}
{Colors.RED}  [9]{Colors.END} 🔄 Server Reboot       {Colors.DIM}(met bevestiging){Colors.END}
{Colors.RED}  [0]{Colors.END} ❌ Exit
{Colors.WHITE}{Colors.BOLD}  {'─' * w}{Colors.END}
""")


def print_step(msg):
    print(f"\n{Colors.BLUE}{Colors.BOLD}==>{Colors.END} {msg}")


def print_success(msg):
    print(f"{Colors.GREEN}✓{Colors.END} {msg}")


def print_warning(msg):
    print(f"{Colors.YELLOW}⚠{Colors.END} {msg}")


def print_error(msg):
    print(f"{Colors.RED}✗{Colors.END} {msg}")


def print_info(msg):
    print(f"{Colors.CYAN}ℹ{Colors.END} {msg}")


def run_local(cmd, check=True, capture=False):
    """Run a local command"""
    if capture:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result
    else:
        result = subprocess.run(cmd, shell=True)
        if check and result.returncode != 0:
            print_error(f"Command failed: {cmd}")
            return None
        return result


def run_ssh(cmd, check=False):
    """Run a command on VPS via SSH (uses SSH alias with multiplexing)"""
    result = subprocess.run(
        ['ssh', SSH_ALIAS, cmd],
        capture_output=True, text=True
    )
    return result


# ============================================================================
# [1] SERVER OVERVIEW
# ============================================================================

def server_overview():
    """Show server overview: uptime, CPU, RAM, disk"""
    print_step("Server Overview")

    cmd = (
        "hostname && echo '---SEP---' && "
        "uptime && echo '---SEP---' && "
        "cat /proc/cpuinfo | grep 'model name' | head -1 && echo '---SEP---' && "
        "nproc && echo '---SEP---' && "
        "free -b | grep Mem && echo '---SEP---' && "
        "free -b | grep Swap && echo '---SEP---' && "
        "df -h / | tail -1 && echo '---SEP---' && "
        "cat /etc/os-release | grep PRETTY_NAME && echo '---SEP---' && "
        "cat /proc/loadavg"
    )

    result = run_ssh(cmd)
    if result.returncode != 0:
        print_error("Kan geen verbinding maken met VPS")
        if result.stderr:
            print(f"{Colors.DIM}{result.stderr.strip()}{Colors.END}")
        return

    parts = result.stdout.split('---SEP---')
    if len(parts) < 9:
        print(result.stdout)
        return

    hostname = parts[0].strip()
    uptime_str = parts[1].strip()
    cpu_model = parts[2].strip().replace('model name\t: ', '').replace('model name  : ', '')
    cpu_cores = parts[3].strip()
    mem_line = parts[4].strip()
    swap_line = parts[5].strip()
    disk_line = parts[6].strip()
    os_info = parts[7].strip().replace('PRETTY_NAME=', '').strip('"')
    loadavg = parts[8].strip().split()

    # Parse memory (free -b output: Mem: total used free shared buff/cache available)
    mem_parts = mem_line.split()
    if len(mem_parts) >= 7:
        mem_total = int(mem_parts[1])
        mem_used = int(mem_parts[2])
        mem_available = int(mem_parts[6])
        mem_pct = round(mem_used / mem_total * 100) if mem_total else 0
        mem_total_gb = f"{mem_total / (1024**3):.1f}G"
        mem_used_gb = f"{mem_used / (1024**3):.1f}G"
        mem_avail_gb = f"{mem_available / (1024**3):.1f}G"
    else:
        mem_total_gb = mem_used_gb = mem_avail_gb = "?"
        mem_pct = 0

    # Parse swap
    swap_parts = swap_line.split()
    if len(swap_parts) >= 3:
        swap_total = int(swap_parts[1])
        swap_used = int(swap_parts[2])
        if swap_total > 0:
            swap_str = f"{swap_used / (1024**3):.1f}G / {swap_total / (1024**3):.1f}G"
        else:
            swap_str = "Disabled"
    else:
        swap_str = "?"

    # Parse disk (df -h output: /dev/vda1 348G 5.8G 342G 2% /)
    disk_parts = disk_line.split()
    if len(disk_parts) >= 6:
        disk_size = disk_parts[1]
        disk_used = disk_parts[2]
        disk_avail = disk_parts[3]
        disk_pct = disk_parts[4]
    else:
        disk_size = disk_used = disk_avail = disk_pct = "?"

    # Parse uptime for cleaner display
    uptime_clean = uptime_str
    if 'up' in uptime_str:
        up_part = uptime_str.split('up')[1].split(',')[0].strip()
        users_match = re.search(r'(\d+)\s+user', uptime_str)
        users = users_match.group(1) if users_match else '?'
        uptime_clean = f"{up_part}, {users} users"

    # Load average
    load_1 = loadavg[0] if len(loadavg) > 0 else '?'
    load_5 = loadavg[1] if len(loadavg) > 1 else '?'
    load_15 = loadavg[2] if len(loadavg) > 2 else '?'

    # Memory color
    if mem_pct > 80:
        mem_color = Colors.RED
    elif mem_pct > 60:
        mem_color = Colors.YELLOW
    else:
        mem_color = Colors.GREEN

    # Disk color
    disk_pct_num = int(disk_pct.rstrip('%')) if disk_pct != '?' else 0
    if disk_pct_num > 80:
        disk_color = Colors.RED
    elif disk_pct_num > 60:
        disk_color = Colors.YELLOW
    else:
        disk_color = Colors.GREEN

    print(f"\n{Colors.CYAN}{'─' * 60}{Colors.END}")
    print(f"  {Colors.BOLD}Hostname:{Colors.END}   {hostname}")
    print(f"  {Colors.BOLD}OS:{Colors.END}         {os_info}")
    print(f"  {Colors.BOLD}Uptime:{Colors.END}     {uptime_clean}")
    print(f"  {Colors.BOLD}CPU:{Colors.END}        {cpu_model} ({cpu_cores} cores)")
    print(f"  {Colors.BOLD}Load:{Colors.END}       {load_1} / {load_5} / {load_15}  {Colors.DIM}(1/5/15 min){Colors.END}")
    print(f"{Colors.CYAN}{'─' * 60}{Colors.END}")
    print(f"  {Colors.BOLD}Memory:{Colors.END}     {mem_color}{mem_used_gb}{Colors.END} / {mem_total_gb}  ({mem_color}{mem_pct}%{Colors.END})  {Colors.DIM}beschikbaar: {mem_avail_gb}{Colors.END}")
    print(f"  {Colors.BOLD}Swap:{Colors.END}       {swap_str}")
    print(f"  {Colors.BOLD}Disk /:{Colors.END}     {disk_color}{disk_used}{Colors.END} / {disk_size}  ({disk_color}{disk_pct}{Colors.END})  {Colors.DIM}vrij: {disk_avail}{Colors.END}")
    print(f"{Colors.CYAN}{'─' * 60}{Colors.END}")


# ============================================================================
# [2] WEBSITES
# ============================================================================

def get_nginx_sites():
    """Parse all nginx sites-enabled configs and return domain info.
    Returns list of dicts with: config, domains, root, proxy_pass"""
    result = run_ssh("ls /etc/nginx/sites-enabled/")
    if result.returncode != 0:
        return []

    configs = [s.strip() for s in result.stdout.strip().split('\n') if s.strip() and s.strip() != 'default']
    sites = []

    for config in configs:
        # Get server_name and root in one call
        info_result = run_ssh(
            f"grep -E 'server_name|root |proxy_pass' /etc/nginx/sites-enabled/{config} 2>/dev/null"
        )
        if info_result.returncode != 0:
            continue

        domains = []
        doc_root = None
        proxy = None

        for line in info_result.stdout.strip().split('\n'):
            line = line.strip()
            if line.startswith('server_name'):
                # Parse: server_name domain.nl www.domain.nl;
                names = line.replace('server_name', '').rstrip(';').strip().split()
                for name in names:
                    name = name.strip()
                    if name and name != '_' and name != 'localhost':
                        domains.append(name)
            elif line.startswith('root '):
                doc_root = line.replace('root ', '').rstrip(';').strip()
            elif 'proxy_pass' in line:
                proxy = line.replace('proxy_pass', '').rstrip(';').strip()

        if domains:
            sites.append({
                'config': config,
                'domains': domains,
                'root': doc_root,
                'proxy': proxy,
            })

    return sites


def websites_overview():
    """Show nginx sites, HTTP status, and document roots (auto-detected from nginx)"""
    print_step("Websites Overview")

    sites = get_nginx_sites()
    if not sites:
        print_error("Kan nginx sites niet ophalen")
        return

    # Collect all unique domains, group by main domain
    main_domains = {}  # main_domain -> [subdomains]
    domain_info = {}   # domain -> site info

    for site in sites:
        for domain in site['domains']:
            domain_info[domain] = site
            # Determine main domain (last 2 parts)
            parts = domain.split('.')
            if len(parts) >= 2:
                main = '.'.join(parts[-2:])
            else:
                main = domain
            if main not in main_domains:
                main_domains[main] = []
            main_domains[main].append(domain)

    print(f"\n{Colors.CYAN}{'─' * 70}{Colors.END}")
    print(f"  {'Domein':<30} {'HTTP':<8} {'Type':<12} {'Locatie'}")
    print(f"{Colors.CYAN}{'─' * 70}{Colors.END}")

    for main_domain in sorted(main_domains.keys()):
        subdomains = sorted(main_domains[main_domain], key=lambda d: (len(d.split('.')), d))

        for domain in subdomains:
            site = domain_info[domain]

            # HTTP check
            http_result = run_local(
                f"curl -s -o /dev/null -w '%{{http_code}}' https://{domain} --max-time 5",
                capture=True
            )
            status_code = http_result.stdout.strip() if http_result.stdout else '---'

            if status_code in ['200', '301', '302', '307']:
                status_color = Colors.GREEN
            elif status_code in ['403', '404']:
                status_color = Colors.YELLOW
            else:
                status_color = Colors.RED

            # Determine type
            if site.get('proxy'):
                site_type = 'proxy'
                location = site['proxy']
            elif site.get('root'):
                site_type = 'static'
                location = site['root']
            else:
                site_type = '?'
                location = 'n/a'

            # Indent subdomains
            is_sub = len(domain.split('.')) > 2
            prefix = '  └ ' if is_sub else ''
            label = f"{prefix}{domain}"

            print(f"  {label:<30} {status_color}{status_code}{Colors.END}     {Colors.DIM}{site_type:<12}{location}{Colors.END}")

        # Visual separator between main domains
        if main_domain != sorted(main_domains.keys())[-1]:
            print(f"{Colors.DIM}  {'·' * 70}{Colors.END}")

    print(f"{Colors.CYAN}{'─' * 70}{Colors.END}")


# ============================================================================
# [3] PM2 MANAGEMENT
# ============================================================================

def pm2_list():
    """List all PM2 processes"""
    print_step("PM2 Processes")
    result = run_ssh("pm2 list")
    if result.returncode == 0:
        print(result.stdout)
    else:
        print_error("Kan PM2 list niet ophalen")
        if result.stderr:
            print(f"{Colors.DIM}{result.stderr.strip()}{Colors.END}")


def pm2_get_processes():
    """Get list of PM2 process names"""
    result = run_ssh("pm2 jlist")
    if result.returncode == 0 and result.stdout.strip():
        import json
        try:
            processes = json.loads(result.stdout.strip())
            return [(p.get('name', '?'), p.get('pm2_env', {}).get('status', '?'), p.get('pm_id', 0)) for p in processes]
        except (json.JSONDecodeError, KeyError):
            return []
    return []


def pm2_select_process(action="select"):
    """Interactive process selection"""
    processes = pm2_get_processes()
    if not processes:
        print_error("Geen PM2 processen gevonden")
        return None

    print(f"\n{Colors.CYAN}Beschikbare PM2 processen:{Colors.END}")
    for i, (name, status, pm_id) in enumerate(processes, 1):
        status_color = Colors.GREEN if status == 'online' else Colors.RED
        print(f"  [{i}] {name} ({status_color}{status}{Colors.END})")
    print(f"  [0] Terug")

    try:
        choice = input(f"\n{Colors.CYAN}Selecteer process om te {action} [0-{len(processes)}]: {Colors.END}").strip()
        if choice == '0' or not choice:
            return None
        idx = int(choice) - 1
        if 0 <= idx < len(processes):
            return processes[idx][0]
    except (ValueError, IndexError):
        pass
    print_error("Ongeldige selectie")
    return None


def pm2_restart_process(name=None):
    """Restart a PM2 process"""
    if not name:
        name = pm2_select_process("herstarten")
    if not name:
        return

    print_step(f"Restarting '{name}'...")
    result = run_ssh(f"pm2 restart {name}")
    if result.returncode == 0:
        print_success(f"Process '{name}' herstart")
    else:
        print_error(f"Kon '{name}' niet herstarten")
        if result.stderr:
            print(result.stderr)


def pm2_stop_process(name=None):
    """Stop a PM2 process"""
    if not name:
        name = pm2_select_process("stoppen")
    if not name:
        return

    print_step(f"Stopping '{name}'...")
    result = run_ssh(f"pm2 stop {name}")
    if result.returncode == 0:
        print_success(f"Process '{name}' gestopt")
    else:
        print_error(f"Kon '{name}' niet stoppen")


def pm2_start_process(name=None):
    """Start a PM2 process"""
    if not name:
        name = pm2_select_process("starten")
    if not name:
        return

    print_step(f"Starting '{name}'...")
    result = run_ssh(f"pm2 start {name}")
    if result.returncode == 0:
        print_success(f"Process '{name}' gestart")
    else:
        print_error(f"Kon '{name}' niet starten")


def pm2_view_logs(name=None, lines=50):
    """View logs for a PM2 process"""
    if not name:
        name = pm2_select_process("logs bekijken van")
    if not name:
        return

    print_step(f"Laatste {lines} regels logs van '{name}'")
    result = run_ssh(f"pm2 logs {name} --lines {lines} --nostream")
    if result.returncode == 0:
        print(result.stdout)
        if result.stderr:
            print(result.stderr)
    else:
        print_error(f"Kon logs niet ophalen voor '{name}'")


def pm2_submenu():
    """PM2 management submenu"""
    while True:
        clear_screen()
        print_logo()
        w = 58
        print(f"""
{Colors.WHITE}{Colors.BOLD}  {'─' * w}
  PM2 PROCESS MANAGEMENT
  {'─' * w}{Colors.END}
{Colors.GREEN}  [1]{Colors.END} 📊 List All Processes   {Colors.DIM}(toon status alle PM2 apps){Colors.END}
{Colors.YELLOW}  [2]{Colors.END} 🔄 Restart Process      {Colors.DIM}(selecteer en herstart){Colors.END}
{Colors.YELLOW}  [3]{Colors.END} ⏹️  Stop Process         {Colors.DIM}(selecteer en stop){Colors.END}
{Colors.YELLOW}  [4]{Colors.END} ▶️  Start Process        {Colors.DIM}(selecteer en start){Colors.END}
{Colors.BLUE}  [5]{Colors.END} 📋 View Logs            {Colors.DIM}(laatste 50 regels){Colors.END}
{Colors.RED}  [0]{Colors.END} ← Terug
{Colors.WHITE}{Colors.BOLD}  {'─' * w}{Colors.END}
""")

        choice = input(f"{Colors.CYAN}Selecteer optie [0-5]: {Colors.END}").strip()

        if choice == '1':
            pm2_list()
        elif choice == '2':
            pm2_restart_process()
        elif choice == '3':
            pm2_stop_process()
        elif choice == '4':
            pm2_start_process()
        elif choice == '5':
            pm2_view_logs()
        elif choice == '0':
            return
        else:
            print_error("Ongeldige optie")

        if choice != '0':
            input(f"\n{Colors.DIM}Druk op Enter om door te gaan...{Colors.END}")


# ============================================================================
# [4] SSL CERTIFICATEN
# ============================================================================

def ssl_certificates():
    """Show SSL certificate expiry dates"""
    print_step("SSL Certificaten")

    result = run_ssh("sudo certbot certificates 2>/dev/null")
    if result.returncode != 0:
        print_error("Kan certbot niet uitvoeren")
        if result.stderr:
            print(f"{Colors.DIM}{result.stderr.strip()}{Colors.END}")
        return

    output = result.stdout
    if not output.strip():
        print_warning("Geen certbot output")
        return

    print(f"\n{Colors.CYAN}{'─' * 60}{Colors.END}")
    print(f"  {'Domein':<35} {'Verloopt':<15} {'Status'}")
    print(f"{Colors.CYAN}{'─' * 60}{Colors.END}")

    # Parse certbot output
    current_domains = None
    for line in output.split('\n'):
        line = line.strip()

        if line.startswith('Domains:'):
            current_domains = line.replace('Domains:', '').strip()
        elif line.startswith('Expiry Date:') and current_domains:
            # Parse: "Expiry Date: 2025-04-15 12:00:00+00:00 (VALID: 89 days)"
            match = re.search(r'(\d{4}-\d{2}-\d{2})', line)
            days_match = re.search(r'(\d+)\s+day', line)

            if match:
                expiry_date = match.group(1)
                days_left = int(days_match.group(1)) if days_match else 0

                if days_left > 30:
                    status_color = Colors.GREEN
                    status = f"{days_left} dagen"
                elif days_left > 7:
                    status_color = Colors.YELLOW
                    status = f"{days_left} dagen"
                else:
                    status_color = Colors.RED
                    status = f"{days_left} dagen!"

                print(f"  {current_domains:<35} {expiry_date:<15} {status_color}{status}{Colors.END}")
            current_domains = None

    print(f"{Colors.CYAN}{'─' * 60}{Colors.END}")


# ============================================================================
# [5] SERVICES
# ============================================================================

def services_status():
    """Show status of key services (auto-detects running services)"""
    print_step("Service Status")

    # Auto-detect: check default services + find php-fpm version dynamically
    result = run_ssh("systemctl list-units --type=service --state=active --no-legend 2>/dev/null | awk '{print $1}'")
    active_services = result.stdout.strip().split('\n') if result.stdout else []

    # Build service list: defaults + auto-detected relevant ones
    services = []
    seen = set()

    # Always check these core services
    for svc in DEFAULT_SERVICES:
        services.append(svc)
        seen.add(svc)

    # Auto-detect php-fpm (any version), pm2, certbot timer etc.
    for svc in active_services:
        svc = svc.strip().replace('.service', '')
        if not svc:
            continue
        # Pick up any php-fpm version
        if 'php' in svc and 'fpm' in svc and svc not in seen:
            services.append(svc)
            seen.add(svc)
        # Pick up other useful services
        if svc in ('ufw', 'cron', 'ssh', 'certbot.timer') and svc not in seen:
            services.append(svc)
            seen.add(svc)

    # Remove duplicates if php version was already in DEFAULT_SERVICES
    # e.g. if php8.3-fpm is default but php8.4-fpm is found
    final_services = []
    php_found = False
    for svc in services:
        if 'php' in svc and 'fpm' in svc:
            if php_found:
                continue
            php_found = True
        final_services.append(svc)

    result = run_ssh(f"systemctl is-active {' '.join(final_services)}")
    statuses = result.stdout.strip().split('\n') if result.stdout else []

    print(f"\n{Colors.CYAN}{'─' * 40}{Colors.END}")
    for i, service in enumerate(final_services):
        status = statuses[i].strip() if i < len(statuses) else 'unknown'
        if status == 'active':
            status_color = Colors.GREEN
            icon = '●'
        else:
            status_color = Colors.RED
            icon = '○'

        print(f"  {status_color}{icon}{Colors.END} {service:<20} {status_color}{status}{Colors.END}")
    print(f"{Colors.CYAN}{'─' * 40}{Colors.END}")


# ============================================================================
# [6] BACKUP STATUS
# ============================================================================

def backup_status():
    """Show backup status"""
    print_step("Backup Status")

    # Last backup log lines
    print(f"\n{Colors.BOLD}  Laatste backup log:{Colors.END}")
    result = run_ssh("tail -5 /var/log/vps-backup.log 2>/dev/null")
    if result.returncode == 0 and result.stdout.strip():
        for line in result.stdout.strip().split('\n'):
            print(f"    {Colors.DIM}{line}{Colors.END}")
    else:
        print_warning("  Geen backup log gevonden")

    # Backup size
    print(f"\n{Colors.BOLD}  Backup grootte:{Colors.END}")
    result = run_ssh("du -sh /var/backups/vps/ 2>/dev/null")
    if result.returncode == 0 and result.stdout.strip():
        print(f"    {result.stdout.strip()}")
    else:
        print_warning("  Geen backup map gevonden")

    # Latest database backups
    print(f"\n{Colors.BOLD}  Laatste database backups:{Colors.END}")
    result = run_ssh("ls -lt /var/backups/vps/databases/ 2>/dev/null | head -5")
    if result.returncode == 0 and result.stdout.strip():
        for line in result.stdout.strip().split('\n'):
            print(f"    {Colors.DIM}{line}{Colors.END}")
    else:
        print_warning("  Geen database backups gevonden")


# ============================================================================
# [7] FIREWALL & SECURITY
# ============================================================================

def firewall_security():
    """Show firewall rules and security info"""
    print_step("Firewall & Security")

    # UFW rules
    print(f"\n{Colors.BOLD}  UFW Firewall Rules:{Colors.END}")
    result = run_ssh("sudo ufw status numbered 2>/dev/null")
    if result.returncode == 0 and result.stdout.strip():
        for line in result.stdout.strip().split('\n'):
            print(f"    {line}")
    else:
        print_warning("  Kan UFW status niet ophalen")

    # fail2ban status
    print(f"\n{Colors.BOLD}  Fail2ban SSHD Status:{Colors.END}")
    result = run_ssh("sudo fail2ban-client status sshd 2>/dev/null")
    if result.returncode == 0 and result.stdout.strip():
        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if 'Currently banned' in line:
                count = line.split(':')[-1].strip()
                color = Colors.RED if int(count) > 0 else Colors.GREEN
                label = line.split(':')[0].strip()
                print(f"    {color}{label}: {count}{Colors.END}  {Colors.DIM}(nu actief){Colors.END}")
            elif 'Total banned' in line:
                count = line.split(':')[-1].strip()
                print(f"    {Colors.YELLOW}{line.split(':')[0].strip()}: {count}{Colors.END}  {Colors.DIM}(sinds boot, verlopen bans inbegrepen){Colors.END}")
            elif 'Banned IP list' in line:
                ip_list = line.split(':')[-1].strip()
                if ip_list:
                    print(f"    {Colors.RED}{line}{Colors.END}")
                else:
                    print(f"    {line}")
            else:
                print(f"    {line}")
    else:
        print_warning("  Kan fail2ban status niet ophalen")

    # Banned IPs across all jails
    print(f"\n{Colors.BOLD}  Banned IPs (alle jails):{Colors.END}")
    result = run_ssh("sudo fail2ban-client banned 2>/dev/null")
    if result.returncode == 0 and result.stdout.strip():
        banned = result.stdout.strip()
        if banned == '[{}]' or banned == '[]':
            print_success("  Geen gebande IPs")
        else:
            print(f"    {Colors.RED}{banned}{Colors.END}")
    else:
        # Fallback: check per jail
        result = run_ssh("sudo fail2ban-client status 2>/dev/null")
        if result.returncode == 0:
            print(f"    {Colors.DIM}{result.stdout.strip()}{Colors.END}")

    # Active SSH connections
    print(f"\n{Colors.BOLD}  Actieve SSH verbindingen:{Colors.END}")
    result = run_ssh("who")
    if result.returncode == 0 and result.stdout.strip():
        for line in result.stdout.strip().split('\n'):
            parts = line.split()
            if len(parts) >= 5:
                user = parts[0]
                tty = parts[1]
                date = f"{parts[2]} {parts[3]}"
                ip = parts[4].strip('()')
                print(f"    {Colors.GREEN}{user}{Colors.END}  {Colors.DIM}{tty:<10}{Colors.END}  {date}  {Colors.CYAN}{ip}{Colors.END}")
            else:
                print(f"    {line}")
    else:
        print_info("  Geen actieve sessies")

    # Recent SSH login attempts
    print(f"\n{Colors.BOLD}  Laatste 10 SSH login pogingen:{Colors.END}")
    result = run_ssh("sudo grep 'sshd' /var/log/auth.log 2>/dev/null | tail -10")
    if result.returncode == 0 and result.stdout.strip():
        for line in result.stdout.strip().split('\n'):
            if 'Accepted' in line:
                print(f"    {Colors.GREEN}{line.strip()}{Colors.END}")
            elif 'Failed' in line or 'Invalid' in line:
                print(f"    {Colors.RED}{line.strip()}{Colors.END}")
            else:
                print(f"    {Colors.DIM}{line.strip()}{Colors.END}")
    else:
        print_warning("  Kan auth.log niet lezen")


# ============================================================================
# [U] SYSTEM UPDATES
# ============================================================================

def system_updates():
    """Check for available system updates"""
    print_step("System Updates")

    # Check for upgradable packages
    print_info("Checking for updates...")
    result = run_ssh("sudo apt update -qq 2>/dev/null && apt list --upgradable 2>/dev/null")
    if result.returncode != 0:
        print_error("Kan updates niet ophalen")
        return

    lines = [l.strip() for l in result.stdout.strip().split('\n') if l.strip() and 'Listing' not in l]

    if not lines:
        print_success("Systeem is up-to-date, geen updates beschikbaar")
    else:
        print_warning(f"{len(lines)} update(s) beschikbaar:")
        print(f"\n{Colors.CYAN}{'─' * 60}{Colors.END}")
        for line in lines:
            # Highlight security updates
            if 'security' in line.lower():
                print(f"  {Colors.RED}{line}{Colors.END}")
            else:
                print(f"  {Colors.YELLOW}{line}{Colors.END}")
        print(f"{Colors.CYAN}{'─' * 60}{Colors.END}")

        answer = input(f"\n{Colors.CYAN}Updates installeren? [y/N]: {Colors.END}").strip().lower()
        if answer == 'y':
            print_info("Updates worden geinstalleerd...")
            result = run_ssh("sudo apt upgrade -y 2>&1")
            if result.returncode == 0:
                print_success("Updates geinstalleerd")
            else:
                print_error("Fout bij installeren updates")
                if result.stderr:
                    print(f"{Colors.DIM}{result.stderr[:500]}{Colors.END}")


# ============================================================================
# [N] NGINX LOGS
# ============================================================================

def nginx_logs():
    """Show recent nginx error and access logs"""
    print_step("Nginx Logs")

    # Error log
    print(f"\n{Colors.BOLD}  Laatste 20 nginx errors:{Colors.END}")
    result = run_ssh("sudo tail -20 /var/log/nginx/error.log 2>/dev/null")
    if result.returncode == 0 and result.stdout.strip():
        for line in result.stdout.strip().split('\n'):
            if 'error' in line.lower() or 'crit' in line.lower():
                print(f"    {Colors.RED}{line.strip()}{Colors.END}")
            elif 'warn' in line.lower():
                print(f"    {Colors.YELLOW}{line.strip()}{Colors.END}")
            else:
                print(f"    {Colors.DIM}{line.strip()}{Colors.END}")
    else:
        print_success("  Geen errors in nginx error.log")

    # Per-site error logs
    print(f"\n{Colors.BOLD}  Error logs per site:{Colors.END}")
    result = run_ssh("ls /var/log/nginx/*error* 2>/dev/null")
    if result.returncode == 0 and result.stdout.strip():
        log_files = [f.strip() for f in result.stdout.strip().split('\n') if f.strip()]
        for log_file in log_files:
            name = os.path.basename(log_file)
            size_result = run_ssh(f"wc -l < {log_file} 2>/dev/null")
            line_count = size_result.stdout.strip() if size_result.returncode == 0 else '?'
            last_result = run_ssh(f"tail -1 {log_file} 2>/dev/null")
            last_line = last_result.stdout.strip()[:80] if last_result.stdout.strip() else 'leeg'

            color = Colors.GREEN if line_count == '0' or last_line == 'leeg' else Colors.YELLOW
            print(f"    {color}{name}{Colors.END}  {Colors.DIM}({line_count} regels) laatste: {last_line}{Colors.END}")

    # Recent access summary (top 5 status codes)
    print(f"\n{Colors.BOLD}  Access log samenvatting (vandaag):{Colors.END}")
    result = run_ssh("sudo awk '{print $9}' /var/log/nginx/access.log 2>/dev/null | sort | uniq -c | sort -rn | head -10")
    if result.returncode == 0 and result.stdout.strip():
        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            parts = line.split()
            if len(parts) == 2:
                count, code = parts
                if code.startswith('2'):
                    color = Colors.GREEN
                elif code.startswith('3'):
                    color = Colors.CYAN
                elif code.startswith('4'):
                    color = Colors.YELLOW
                elif code.startswith('5'):
                    color = Colors.RED
                else:
                    color = Colors.DIM
                print(f"    {color}HTTP {code}{Colors.END}  {count}x")
    else:
        print_info("  Geen access log data")


# ============================================================================
# [D] DATABASES
# ============================================================================

def database_info():
    """Show MariaDB databases with sizes"""
    print_step("MariaDB Databases")

    cmd = (
        "sudo mysql -e \""
        "SELECT table_schema AS db, "
        "ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS size_mb, "
        "COUNT(*) AS tables "
        "FROM information_schema.tables "
        "WHERE table_schema NOT IN ('information_schema','performance_schema','mysql','sys') "
        "GROUP BY table_schema "
        "ORDER BY size_mb DESC;\" 2>/dev/null"
    )

    result = run_ssh(cmd)
    if result.returncode != 0:
        print_error("Kan databases niet ophalen")
        return

    lines = [l for l in result.stdout.strip().split('\n') if l.strip()]
    if len(lines) <= 1:
        print_warning("Geen databases gevonden")
        return

    print(f"\n{Colors.CYAN}{'─' * 50}{Colors.END}")
    print(f"  {'Database':<25} {'Grootte':<12} {'Tabellen'}")
    print(f"{Colors.CYAN}{'─' * 50}{Colors.END}")

    for line in lines[1:]:  # Skip header
        parts = line.split('\t')
        if len(parts) >= 3:
            db_name = parts[0].strip()
            size = parts[1].strip()
            tables = parts[2].strip()
            print(f"  {Colors.GREEN}{db_name:<25}{Colors.END} {size} MB      {Colors.DIM}{tables}{Colors.END}")

    print(f"{Colors.CYAN}{'─' * 50}{Colors.END}")


# ============================================================================
# [C] CRONJOBS
# ============================================================================

def cronjobs():
    """Show scheduled cron tasks"""
    print_step("Cronjobs")

    # Root crontab
    print(f"\n{Colors.BOLD}  Root crontab:{Colors.END}")
    result = run_ssh("sudo crontab -l 2>/dev/null")
    if result.returncode == 0 and result.stdout.strip():
        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if line.startswith('#'):
                print(f"    {Colors.DIM}{line}{Colors.END}")
            elif line:
                print(f"    {Colors.GREEN}{line}{Colors.END}")
    else:
        print_info("  Geen root crontab")

    # User crontab
    print(f"\n{Colors.BOLD}  {VPS_USER} crontab:{Colors.END}")
    result = run_ssh("crontab -l 2>/dev/null")
    if result.returncode == 0 and result.stdout.strip():
        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if line.startswith('#'):
                print(f"    {Colors.DIM}{line}{Colors.END}")
            elif line:
                print(f"    {Colors.GREEN}{line}{Colors.END}")
    else:
        print_info(f"  Geen {VPS_USER} crontab")

    # Systemd timers
    print(f"\n{Colors.BOLD}  Systemd timers:{Colors.END}")
    result = run_ssh("systemctl list-timers --no-pager 2>/dev/null")
    if result.returncode == 0 and result.stdout.strip():
        for line in result.stdout.strip().split('\n'):
            print(f"    {Colors.DIM}{line}{Colors.END}")
    else:
        print_info("  Geen systemd timers")


# ============================================================================
# [S] DISK PER SITE
# ============================================================================

def disk_per_site():
    """Show disk usage per site in /var/www"""
    print_step("Disk per Site")

    result = run_ssh("du -sh /var/www/*/ 2>/dev/null | sort -rh")
    if result.returncode != 0 or not result.stdout.strip():
        print_error("Kan disk gebruik niet ophalen")
        return

    print(f"\n{Colors.CYAN}{'─' * 50}{Colors.END}")
    print(f"  {'Grootte':<12} {'Site'}")
    print(f"{Colors.CYAN}{'─' * 50}{Colors.END}")

    for line in result.stdout.strip().split('\n'):
        parts = line.split('\t')
        if len(parts) >= 2:
            size = parts[0].strip()
            path = parts[1].strip().rstrip('/')
            site_name = os.path.basename(path)

            # Color based on size
            size_val = size.rstrip('KMGT')
            try:
                num = float(size_val)
                unit = size[-1] if size[-1] in 'KMGT' else ''
                if unit == 'G' and num > 1:
                    color = Colors.RED
                elif unit == 'G' or (unit == 'M' and num > 500):
                    color = Colors.YELLOW
                else:
                    color = Colors.GREEN
            except ValueError:
                color = Colors.DIM

            print(f"  {color}{size:<12}{Colors.END} {site_name}")

    # Total /var/www
    total_result = run_ssh("du -sh /var/www/ 2>/dev/null")
    if total_result.returncode == 0 and total_result.stdout.strip():
        total_size = total_result.stdout.strip().split('\t')[0]
        print(f"{Colors.CYAN}{'─' * 50}{Colors.END}")
        print(f"  {Colors.BOLD}{total_size:<12} TOTAAL{Colors.END}")

    print(f"{Colors.CYAN}{'─' * 50}{Colors.END}")


# ============================================================================
# [8] DEPLOY SITE
# ============================================================================

def deploy_site(site_name=None):
    """Deploy a site to VPS via rsync"""
    if site_name and site_name not in SITES:
        print_error(f"Onbekende site: {site_name}")
        print_info(f"Beschikbare sites: {', '.join(SITES.keys())}")
        return False

    if not site_name:
        # Show deploy submenu
        deploy_submenu()
        return True

    return _do_deploy(site_name)


def _do_deploy(site_name):
    """Execute deployment for a specific site"""
    site = SITES[site_name]
    site_type = site['type']

    print_step(f"Deploying {site_name} ({site_type})")

    if site_type == 'static':
        return _deploy_static(site_name, site)
    elif site_type == 'expo+php':
        return _deploy_expo_php(site_name, site)
    elif site_type == 'nextjs':
        return _deploy_nextjs(site_name, site)
    else:
        print_error(f"Onbekend site type: {site_type}")
        return False


def _deploy_static(site_name, site):
    """Deploy static site"""
    local = site['local']
    remote = site['remote']

    if not os.path.isdir(local):
        print_error(f"Lokale map niet gevonden: {local}")
        return False

    print_info(f"Rsync: {local} -> {SSH_ALIAS}:{remote}")

    rsync_cmd = (
        f'rsync -avz --delete '
        f'--exclude ".git" '
        f'--exclude ".DS_Store" '
        f'"{local}" '
        f'{SSH_ALIAS}:"{remote}"'
    )

    result = run_local(rsync_cmd)
    if result and result.returncode == 0:
        print_success(f"{site_name} deployed")

        # Ask to reload nginx
        answer = input(f"\n{Colors.CYAN}Nginx herladen? [y/N]: {Colors.END}").strip().lower()
        if answer == 'y':
            result = run_ssh("sudo systemctl reload nginx")
            if result.returncode == 0:
                print_success("Nginx herlaad")
            else:
                print_error("Nginx reload failed")
        return True

    print_error(f"Deploy {site_name} failed")
    return False


def _deploy_expo_php(site_name, site):
    """Deploy Expo + PHP site (home.dmmusic.nl)"""
    # Deploy frontend
    local_fe = site['local_frontend']
    remote_fe = site['remote_frontend']
    local_api = site['local_api']
    remote_api = site['remote_api']

    success = True

    # Frontend
    if os.path.isdir(local_fe):
        print_info(f"Frontend: {local_fe} -> {SSH_ALIAS}:{remote_fe}")
        rsync_cmd = (
            f'rsync -avz --delete '
            f'--exclude ".git" '
            f'--exclude ".DS_Store" '
            f'"{local_fe}" '
            f'{SSH_ALIAS}:"{remote_fe}"'
        )
        result = run_local(rsync_cmd)
        if result and result.returncode == 0:
            print_success("Frontend deployed")
        else:
            print_error("Frontend deploy failed")
            success = False
    else:
        print_warning(f"Frontend map niet gevonden: {local_fe}")

    # API
    if os.path.isdir(local_api):
        print_info(f"API: {local_api} -> {SSH_ALIAS}:{remote_api}")
        rsync_cmd = (
            f'rsync -avz --delete '
            f'--exclude ".git" '
            f'--exclude ".DS_Store" '
            f'--exclude "uploads" '
            f'"{local_api}" '
            f'{SSH_ALIAS}:"{remote_api}"'
        )
        result = run_local(rsync_cmd)
        if result and result.returncode == 0:
            print_success("API deployed")
        else:
            print_error("API deploy failed")
            success = False
    else:
        print_warning(f"API map niet gevonden: {local_api}")

    if success:
        print_success(f"{site_name} deployed")

        answer = input(f"\n{Colors.CYAN}Nginx herladen? [y/N]: {Colors.END}").strip().lower()
        if answer == 'y':
            result = run_ssh("sudo systemctl reload nginx")
            if result.returncode == 0:
                print_success("Nginx herlaad")

    return success


def _deploy_nextjs(site_name, site):
    """Deploy Next.js site (aanvraag.dmmusic.nl)"""
    local = site['local']
    remote = site['remote']
    pm2_name = site.get('pm2_name')
    excludes = site.get('exclude', [])

    if not os.path.isdir(local):
        print_error(f"Lokale map niet gevonden: {local}")
        return False

    exclude_args = ' '.join([f'--exclude "{e}"' for e in excludes])

    print_info(f"Rsync: {local} -> {SSH_ALIAS}:{remote}")
    rsync_cmd = (
        f'rsync -avz --delete '
        f'{exclude_args} '
        f'--exclude ".DS_Store" '
        f'"{local}" '
        f'{SSH_ALIAS}:"{remote}"'
    )

    result = run_local(rsync_cmd)
    if result and result.returncode == 0:
        print_success(f"{site_name} files synced")

        # Install dependencies on remote
        print_info("Installing dependencies on VPS...")
        install_result = run_ssh(f"cd {remote} && npm install --production")
        if install_result.returncode == 0:
            print_success("Dependencies installed")
        else:
            print_warning("npm install had issues")

        # Build on remote
        print_info("Building on VPS...")
        build_result = run_ssh(f"cd {remote} && npm run build")
        if build_result.returncode == 0:
            print_success("Build completed")
        else:
            print_error("Build failed")
            if build_result.stderr:
                print(f"{Colors.DIM}{build_result.stderr[:500]}{Colors.END}")

        # Restart PM2
        if pm2_name:
            print_info(f"Restarting PM2 process '{pm2_name}'...")
            restart_result = run_ssh(f"pm2 restart {pm2_name}")
            if restart_result.returncode == 0:
                print_success(f"PM2 '{pm2_name}' herstart")
            else:
                print_error(f"PM2 restart failed voor '{pm2_name}'")

        print_success(f"{site_name} deployed")
        return True

    print_error(f"Deploy {site_name} failed")
    return False


def deploy_submenu():
    """Deploy site submenu"""
    while True:
        clear_screen()
        print_logo()
        w = 58
        print(f"""
{Colors.WHITE}{Colors.BOLD}  {'─' * w}
  DEPLOY SITE
  {'─' * w}{Colors.END}
{Colors.GREEN}  [1]{Colors.END} 🌐 djmartijn.nl        {Colors.DIM}(rsync static files){Colors.END}
{Colors.GREEN}  [2]{Colors.END} 🌐 blenderdjshow.nl    {Colors.DIM}(rsync static files){Colors.END}
{Colors.YELLOW}  [3]{Colors.END} 🌐 home.dmmusic.nl     {Colors.DIM}(rsync frontend + API){Colors.END}
{Colors.MAGENTA}  [4]{Colors.END} 🌐 aanvraag.dmmusic.nl {Colors.DIM}(rsync + build + PM2 restart){Colors.END}
{Colors.RED}  [0]{Colors.END} ← Terug
{Colors.WHITE}{Colors.BOLD}  {'─' * w}{Colors.END}
""")

        choice = input(f"{Colors.CYAN}Selecteer site [0-4]: {Colors.END}").strip()

        site_map = {
            '1': 'djmartijn.nl',
            '2': 'blenderdjshow.nl',
            '3': 'home.dmmusic.nl',
            '4': 'aanvraag.dmmusic.nl',
        }

        if choice in site_map:
            _do_deploy(site_map[choice])
        elif choice == '0':
            return
        else:
            print_error("Ongeldige optie")

        if choice != '0':
            input(f"\n{Colors.DIM}Druk op Enter om door te gaan...{Colors.END}")


# ============================================================================
# [9] SERVER REBOOT
# ============================================================================

def server_reboot():
    """Reboot VPS with confirmation"""
    print_step("Server Reboot")

    print(f"\n{Colors.RED}{Colors.BOLD}  WAARSCHUWING: Dit herstart de VPS ({VPS_HOST})!{Colors.END}")
    print(f"{Colors.DIM}  Alle services worden tijdelijk onbereikbaar.{Colors.END}\n")

    answer = input(f"{Colors.RED}Weet je het zeker? [y/N]: {Colors.END}").strip().lower()
    if answer != 'y':
        print_warning("Reboot geannuleerd")
        return

    print_info("Server wordt herstart...")
    result = run_ssh("sudo reboot")

    if result.returncode != 0 and 'closed' not in (result.stderr or '').lower():
        print_error("Reboot commando mislukt")
        return

    print_info("Wachten tot server weer online is...")
    time.sleep(10)

    # Ping loop to wait for server to come back
    max_attempts = 30
    for attempt in range(max_attempts):
        ping_result = run_local(f"ping -c 1 -W 2 {VPS_HOST}", capture=True)
        if ping_result.returncode == 0:
            print_success(f"Server is weer online! (na {(attempt + 1) * 5} seconden)")

            # Wait a bit more for services to start
            print_info("Wachten op services...")
            time.sleep(10)

            # Verify SSH
            ssh_result = run_ssh("uptime")
            if ssh_result.returncode == 0:
                print_success(f"SSH verbinding OK: {ssh_result.stdout.strip()}")
            else:
                print_warning("SSH nog niet beschikbaar, probeer later opnieuw")
            return

        sys.stdout.write(f"\r{Colors.DIM}  Poging {attempt + 1}/{max_attempts}...{Colors.END}  ")
        sys.stdout.flush()
        time.sleep(5)

    print()
    print_error(f"Server reageert niet na {max_attempts * 5} seconden")
    print_warning(f"Controleer handmatig: ssh {SSH_ALIAS}")


# ============================================================================
# ALL-IN-ONE OVERVIEW
# ============================================================================

def all_overview():
    """Show everything in one overview"""
    server_overview()
    services_status()
    websites_overview()
    pm2_list()
    ssl_certificates()
    backup_status()
    firewall_security()
    system_updates()
    database_info()
    disk_per_site()
    cronjobs()


# ============================================================================
# INTERACTIVE MENU
# ============================================================================

def interactive_menu():
    """Run interactive menu"""
    while True:
        clear_screen()
        print_logo()
        print_menu()

        choice = input(f"{Colors.CYAN}Selecteer optie [0-9/U/N/D/C/S]: {Colors.END}").strip().upper()

        if choice == '1':
            server_overview()
        elif choice == '2':
            websites_overview()
        elif choice == '3':
            pm2_submenu()
            continue
        elif choice == '4':
            ssl_certificates()
        elif choice == '5':
            services_status()
        elif choice == '6':
            backup_status()
        elif choice == '7':
            firewall_security()
        elif choice == '8':
            deploy_submenu()
            continue
        elif choice == 'U':
            system_updates()
        elif choice == 'N':
            nginx_logs()
        elif choice == 'D':
            database_info()
        elif choice == 'C':
            cronjobs()
        elif choice == 'S':
            disk_per_site()
        elif choice == '9':
            server_reboot()
        elif choice == '0':
            print(f"\n{Colors.CYAN}Tot ziens!{Colors.END}\n")
            sys.exit(0)
        else:
            print_error("Ongeldige optie")

        if choice != '0':
            input(f"\n{Colors.DIM}Druk op Enter om door te gaan...{Colors.END}")


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='VPS Manager - Interactive Management Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python vps-manager.py                    # Interactief menu
  python vps-manager.py --status           # Server overview
  python vps-manager.py --sites            # Websites overzicht
  python vps-manager.py --pm2              # PM2 list
  python vps-manager.py --ssl              # SSL certificaten
  python vps-manager.py --services         # Service status
  python vps-manager.py --backup           # Backup status
  python vps-manager.py --deploy SITE      # Deploy specifieke site
  python vps-manager.py --firewall         # Firewall status
  python vps-manager.py --updates          # Beschikbare updates
  python vps-manager.py --nginx-logs       # Nginx logs
  python vps-manager.py --databases        # Database groottes
  python vps-manager.py --cron             # Cronjobs
  python vps-manager.py --disk             # Disk per site
  python vps-manager.py --reboot           # Server reboot
  python vps-manager.py --all              # Alles in één overzicht
        """
    )

    parser.add_argument('--status', action='store_true', help='Server overview')
    parser.add_argument('--sites', action='store_true', help='Websites overzicht')
    parser.add_argument('--pm2', action='store_true', help='PM2 process list')
    parser.add_argument('--ssl', action='store_true', help='SSL certificaten')
    parser.add_argument('--services', action='store_true', help='Service status')
    parser.add_argument('--backup', action='store_true', help='Backup status')
    parser.add_argument('--deploy', metavar='SITE', help='Deploy specifieke site')
    parser.add_argument('--reboot', action='store_true', help='Server reboot')
    parser.add_argument('--firewall', action='store_true', help='Firewall & security status')
    parser.add_argument('--updates', action='store_true', help='System updates check')
    parser.add_argument('--nginx-logs', action='store_true', help='Nginx error/access logs')
    parser.add_argument('--databases', action='store_true', help='MariaDB databases + groottes')
    parser.add_argument('--cron', action='store_true', help='Cronjobs overzicht')
    parser.add_argument('--disk', action='store_true', help='Disk per site')
    parser.add_argument('--all', action='store_true', help='Alles in één overzicht')

    args = parser.parse_args()

    # Non-interactive mode
    if args.status:
        print_logo()
        server_overview()
    elif args.sites:
        print_logo()
        websites_overview()
    elif args.pm2:
        print_logo()
        pm2_list()
    elif args.ssl:
        print_logo()
        ssl_certificates()
    elif args.services:
        print_logo()
        services_status()
    elif args.backup:
        print_logo()
        backup_status()
    elif args.deploy:
        print_logo()
        deploy_site(args.deploy)
    elif args.reboot:
        print_logo()
        server_reboot()
    elif args.firewall:
        print_logo()
        firewall_security()
    elif args.updates:
        print_logo()
        system_updates()
    elif args.nginx_logs:
        print_logo()
        nginx_logs()
    elif args.databases:
        print_logo()
        database_info()
    elif args.cron:
        print_logo()
        cronjobs()
    elif args.disk:
        print_logo()
        disk_per_site()
    elif args.all:
        print_logo()
        all_overview()
    else:
        # Interactive mode
        interactive_menu()


if __name__ == "__main__":
    main()

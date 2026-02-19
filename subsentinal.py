#!/usr/bin/env python3
"""
SubDomain Sentinel v5.1.0 - Complete Enterprise Subdomain Takeover Scanner
================================================================
FULL UPGRADED VERSION WITH ALL FIXES:
- httpx integration for better HTTP analysis
- Shows ALL subdomains in reports (not filtered)
- Fixed crt.sh blocking issues
- Enhanced HTML reports with search/filter
- Zero false positive logic
- Subfinder auto-integration
- Brute-force enumeration option
- Fixed NoneType formatting bug

Author: Vimal T
License: MIT
"""

import argparse
import asyncio
import json
import ssl
import socket
import sys
import time
import csv
import os
import re
import shutil
import tempfile
import subprocess
import hashlib
import random
import string
import logging
import html
import ipaddress
import httpx
from httpx import AsyncClient, Timeout
from typing import List, Set, Dict, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict, field
from enum import Enum, auto
from urllib.parse import urlparse, urlunparse
from collections import defaultdict, Counter
from concurrent.futures import ThreadPoolExecutor
import gzip
import base64
import signal

# Third-party imports
import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector
import dns.resolver
import dns.asyncresolver
import dns.exception
import tldextract

# Optional rich output
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
    from rich.panel import Panel
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Optional color output
try:
    import colorama
    from colorama import Fore, Style, Back, init as colorama_init
    colorama_init(autoreset=True)
    COLOR_AVAILABLE = True
except ImportError:
    COLOR_AVAILABLE = False

# ============================================================================
# CONSTANTS & CONFIGURATION
# ============================================================================

VERSION = "5.1.0"  # Advanced takeover detection: NS delegation, SSL mismatch, header fingerprinting
AUTHOR = "Vimal T"
BANNER = f"""
╔══════════════════════════════════════════════════════════════╗
║                      SubDomain Sentinel v{5.1.0}                    ║
║           Enterprise Subdomain Takeover Scanner                    ║
╚══════════════════════════════════════════════════════════════╝
"""

# Service provider configurations
PROVIDER_CONFIGS = {
    "github": {
        "cname_patterns": [".github.io", ".github.com", "github.map.fastly.net"],
        "error_patterns": [
            "There isn't a GitHub Pages site here.",
            "Project site could not be found",
            "Check your DNS settings",
            "This site is not configured"
        ],
        "claimed_indicators": ["This site is powered by GitHub Pages", "githubusercontent"],
        "status_codes": [404, 410],
        "takeover_url": "https://github.com/settings/pages",
        "verification_method": "create_repo",
        "risk_level": "HIGH",
        "can_takeover": True
    },
    "aws_s3": {
        "cname_patterns": [
            ".s3.amazonaws.com",
            ".s3-website-",
            ".s3.",
            "s3.amazonaws.com",
            ".s3.dualstack."
        ],
        "error_patterns": [
            "NoSuchBucket",
            "The specified bucket does not exist",
            "PermanentRedirect",
            "InvalidBucketName",
            "BucketRegionError"
        ],
        "claimed_indicators": ["ListBucketResult", "IndexDocument", "Contents"],
        "status_codes": [404, 403, 400],
        "takeover_url": "https://s3.console.aws.amazon.com",
        "verification_method": "create_bucket",
        "risk_level": "CRITICAL",
        "can_takeover": True
    },
    "cloudfront": {
        "cname_patterns": [".cloudfront.net"],
        "error_patterns": [
            "ERROR: The request could not be satisfied",
            "Bad request",
            "The distribution does not exist",
            "CloudFront error"
        ],
        "claimed_indicators": [],
        "status_codes": [404, 403, 400],
        "takeover_url": "https://console.aws.amazon.com/cloudfront",
        "verification_method": "claim_distribution",
        "risk_level": "CRITICAL",
        "can_takeover": True
    },
    "heroku": {
        "cname_patterns": [".herokuapp.com", ".herokudns.com"],
        "error_patterns": [
            "no such app",
            "Heroku | No such app",
            "There's nothing here, yet.",
            "herokuapp.com"
        ],
        "claimed_indicators": ["heroku", "Heroku"],
        "status_codes": [404],
        "takeover_url": "https://dashboard.heroku.com",
        "verification_method": "create_app",
        "risk_level": "HIGH",
        "can_takeover": True
    },
    "vercel": {
        "cname_patterns": [".vercel.app", ".now.sh", ".zeit.co"],
        "error_patterns": [
            "The deployment could not be found",
            "The deployment not found",
            "deployment not found (404)",
            "This deployment could not be found"
        ],
        "claimed_indicators": ["Vercel", "Powered by Vercel"],
        "status_codes": [404],
        "takeover_url": "https://vercel.com/dashboard",
        "verification_method": "create_deployment",
        "risk_level": "HIGH",
        "can_takeover": True
    },
    "netlify": {
        "cname_patterns": [".netlify.app", ".netlify.com"],
        "error_patterns": [
            "Not found - Request ID",
            "The page you are looking for doesn't exist",
            "Site not found",
            "Netlify error"
        ],
        "claimed_indicators": ["Netlify", "Deploys by Netlify"],
        "status_codes": [404],
        "takeover_url": "https://app.netlify.com",
        "verification_method": "create_site",
        "risk_level": "HIGH",
        "can_takeover": True
    },
    "firebase": {
        "cname_patterns": [".web.app", ".firebaseapp.com"],
        "error_patterns": [
            "The requested URL was not found on this server",
            "Firebase Hosting Setup",
            "Site not found"
        ],
        "claimed_indicators": ["Firebase", "Hosting by Firebase"],
        "status_codes": [404],
        "takeover_url": "https://console.firebase.google.com",
        "verification_method": "create_hosting",
        "risk_level": "HIGH",
        "can_takeover": True
    },
    "azure": {
        "cname_patterns": [
            ".azurewebsites.net",
            ".azureedge.net",
            ".azure-api.net",
            ".blob.core.windows.net"
        ],
        "error_patterns": [
            "The site you are looking for cannot be found",
            "The resource you are looking for has been removed",
            "No web app is configured at this URL",
            "Azure error"
        ],
        "claimed_indicators": ["Microsoft Azure", "App Service"],
        "status_codes": [404],
        "takeover_url": "https://portal.azure.com",
        "verification_method": "create_resource",
        "risk_level": "HIGH",
        "can_takeover": True
    },
    "cloudflare": {
        "cname_patterns": [".workers.dev", ".pages.dev", "cloudflare.net"],
        "error_patterns": [
            "Worker not found",
            "This worker is not currently deployed",
            "404 Not Found",
            "Cloudflare error"
        ],
        "claimed_indicators": ["Cloudflare", "Workers"],
        "status_codes": [404],
        "takeover_url": "https://dash.cloudflare.com",
        "verification_method": "create_worker",
        "risk_level": "MEDIUM",
        "can_takeover": False
    },
    "fastly": {
        "cname_patterns": [".fastly.net", ".fastly.map.fastly.net"],
        "error_patterns": [
            "Fastly error: unknown domain",
            "Please check that this domain has been added to a service",
            "Fastly error"
        ],
        "claimed_indicators": ["Fastly"],
        "status_codes": [404],
        "takeover_url": "https://manage.fastly.com",
        "verification_method": "claim_domain",
        "risk_level": "MEDIUM",
        "can_takeover": True
    },
    "shopify": {
        "cname_patterns": [".myshopify.com", "shops.myshopify.com"],
        "error_patterns": [
            "Sorry, this shop is currently unavailable",
            "Only one step left!",
            "Sorry, this shop is currently unavailable."
        ],
        "claimed_indicators": ["Shopify", "shopify"],
        "status_codes": [404],
        "takeover_url": "https://partners.shopify.com",
        "verification_method": "create_store",
        "risk_level": "HIGH",
        "can_takeover": True
    },
    "tumblr": {
        "cname_patterns": [".tumblr.com", "domains.tumblr.com"],
        "error_patterns": [
            "There's nothing here.",
            "Whatever you were looking for doesn't currently exist at this address",
            "Not found."
        ],
        "claimed_indicators": ["Tumblr", "tumblr"],
        "status_codes": [404],
        "takeover_url": "https://www.tumblr.com/register",
        "verification_method": "create_blog",
        "risk_level": "HIGH",
        "can_takeover": True
    },
    "wordpress": {
        "cname_patterns": [".wordpress.com"],
        "error_patterns": [
            "Do you want to register",
            "doesn't exist"
        ],
        "claimed_indicators": ["WordPress.com"],
        "status_codes": [404],
        "takeover_url": "https://wordpress.com",
        "verification_method": "create_site",
        "risk_level": "HIGH",
        "can_takeover": True
    },
    "pantheon": {
        "cname_patterns": [".pantheonsite.io", ".pantheon.io"],
        "error_patterns": [
            "404 error unknown site!",
            "The gods are wise",
            "You don't have a site configured at this hostname"
        ],
        "claimed_indicators": ["Pantheon"],
        "status_codes": [404],
        "takeover_url": "https://dashboard.pantheon.io",
        "verification_method": "create_site",
        "risk_level": "HIGH",
        "can_takeover": True
    },
    "surge": {
        "cname_patterns": [".surge.sh"],
        "error_patterns": [
            "project not found",
            "To learn more about Surge"
        ],
        "claimed_indicators": ["Surge"],
        "status_codes": [404],
        "takeover_url": "https://surge.sh",
        "verification_method": "surge_publish",
        "risk_level": "MEDIUM",
        "can_takeover": True
    },
    "bitbucket": {
        "cname_patterns": [".bitbucket.io", ".bitbucket.org"],
        "error_patterns": [
            "Repository not found",
            "The page you have requested does not exist"
        ],
        "claimed_indicators": ["Bitbucket", "Atlassian"],
        "status_codes": [404],
        "takeover_url": "https://bitbucket.org",
        "verification_method": "create_repo",
        "risk_level": "HIGH",
        "can_takeover": True
    },
    "gitlab": {
        "cname_patterns": [".gitlab.io"],
        "error_patterns": [
            "The page you're looking for could not be found",
            "Isn't this a great place for your new project"
        ],
        "claimed_indicators": ["GitLab"],
        "status_codes": [404],
        "takeover_url": "https://gitlab.com",
        "verification_method": "create_pages",
        "risk_level": "HIGH",
        "can_takeover": True
    },
    "fly_io": {
        "cname_patterns": [".fly.dev", ".edgeapp.net"],
        "error_patterns": [
            "404 Not Found",
            "This site doesn't exist yet"
        ],
        "claimed_indicators": ["Fly.io"],
        "status_codes": [404],
        "takeover_url": "https://fly.io/dashboard",
        "verification_method": "create_app",
        "risk_level": "MEDIUM",
        "can_takeover": True
    },
    "render": {
        "cname_patterns": [".onrender.com"],
        "error_patterns": [
            "Not Found",
            "This page could not be found"
        ],
        "claimed_indicators": ["Render"],
        "status_codes": [404],
        "takeover_url": "https://dashboard.render.com",
        "verification_method": "create_service",
        "risk_level": "MEDIUM",
        "can_takeover": True
    },
    "cargo": {
        "cname_patterns": [".cargo.site", ".cargocollective.com"],
        "error_patterns": [
            "404 Not Found",
            "If you're moving your domain away from Cargo"
        ],
        "claimed_indicators": ["Cargo"],
        "status_codes": [404],
        "takeover_url": "https://cargo.site",
        "verification_method": "create_site",
        "risk_level": "MEDIUM",
        "can_takeover": True
    },
    "zendesk": {
        "cname_patterns": [".zendesk.com", ".zendesk.io"],
        "error_patterns": [
            "Help Center Closed",
            "This help center no longer exists",
            "Oops, this help center no longer exists"
        ],
        "claimed_indicators": ["Zendesk"],
        "status_codes": [404],
        "takeover_url": "https://www.zendesk.com",
        "verification_method": "create_subdomain",
        "risk_level": "MEDIUM",
        "can_takeover": True
    },
    "ghost": {
        "cname_patterns": [".ghost.io", ".ghost.org"],
        "error_patterns": [
            "The thing you were looking for is no longer here",
            "404 — Page not found"
        ],
        "claimed_indicators": ["Ghost", "Powered by Ghost"],
        "status_codes": [404],
        "takeover_url": "https://ghost.org",
        "verification_method": "create_site",
        "risk_level": "HIGH",
        "can_takeover": True
    },
    "desk": {
        "cname_patterns": [".desk.com"],
        "error_patterns": [
            "Please try again or try Desk.com free",
            "Sorry, We Couldn't Find That Page"
        ],
        "claimed_indicators": ["Desk.com"],
        "status_codes": [404],
        "takeover_url": "https://www.desk.com",
        "verification_method": "create_site",
        "risk_level": "MEDIUM",
        "can_takeover": True
    },
    "unbounce": {
        "cname_patterns": [".unbounce.com", "unbouncepages.com"],
        "error_patterns": [
            "The requested URL was not found on this server",
            "The page you were looking for doesn't exist"
        ],
        "claimed_indicators": ["Unbounce"],
        "status_codes": [404],
        "takeover_url": "https://unbounce.com",
        "verification_method": "create_page",
        "risk_level": "HIGH",
        "can_takeover": True
    },
    "tilda": {
        "cname_patterns": [".tilda.ws", "tilda.cc"],
        "error_patterns": [
            "Please renew your subscription",
            "Domain is not configured"
        ],
        "claimed_indicators": ["Tilda"],
        "status_codes": [404],
        "takeover_url": "https://tilda.cc",
        "verification_method": "create_site",
        "risk_level": "MEDIUM",
        "can_takeover": True
    },
    "helpscout": {
        "cname_patterns": [".helpscoutdocs.com", "docs.helpscout.net"],
        "error_patterns": [
            "No settings were found for this company",
            "This page is reserved for a Help Scout"
        ],
        "claimed_indicators": ["Help Scout"],
        "status_codes": [404],
        "takeover_url": "https://www.helpscout.com",
        "verification_method": "create_site",
        "risk_level": "MEDIUM",
        "can_takeover": True
    },
    "uservoice": {
        "cname_patterns": [".uservoice.com"],
        "error_patterns": [
            "This UserVoice subdomain is currently available",
            "You\'re almost there"
        ],
        "claimed_indicators": ["UserVoice"],
        "status_codes": [404],
        "takeover_url": "https://www.uservoice.com",
        "verification_method": "create_forum",
        "risk_level": "HIGH",
        "can_takeover": True
    },
    "readme": {
        "cname_patterns": [".readme.io", "readme.com"],
        "error_patterns": [
            "Project doesnt exist",
            "Project not found"
        ],
        "claimed_indicators": ["ReadMe"],
        "status_codes": [404],
        "takeover_url": "https://readme.com",
        "verification_method": "create_project",
        "risk_level": "MEDIUM",
        "can_takeover": True
    },
    "strikingly": {
        "cname_patterns": [".strikinglydns.com", ".s.strikinglydns.com"],
        "error_patterns": [
            "But if you're looking to build your own website",
            "page not found"
        ],
        "claimed_indicators": ["Strikingly"],
        "status_codes": [404],
        "takeover_url": "https://www.strikingly.com",
        "verification_method": "create_site",
        "risk_level": "HIGH",
        "can_takeover": True
    },
    "launchrock": {
        "cname_patterns": [".launchrock.com"],
        "error_patterns": [
            "It looks like you may have taken a wrong turn somewhere"
        ],
        "claimed_indicators": ["LaunchRock"],
        "status_codes": [404],
        "takeover_url": "https://www.launchrock.com",
        "verification_method": "create_site",
        "risk_level": "MEDIUM",
        "can_takeover": True
    },
    "feedpress": {
        "cname_patterns": ["redirect.feedpress.me", ".feedpress.me"],
        "error_patterns": [
            "The feed has not been found",
            "This feed does not exist"
        ],
        "claimed_indicators": ["Feedpress"],
        "status_codes": [404],
        "takeover_url": "https://feed.press",
        "verification_method": "create_feed",
        "risk_level": "MEDIUM",
        "can_takeover": True
    },
    "teamwork": {
        "cname_patterns": [".teamwork.com"],
        "error_patterns": [
            "Oops - We didn't find your site",
            "There is no such site on our platform"
        ],
        "claimed_indicators": ["Teamwork"],
        "status_codes": [404],
        "takeover_url": "https://www.teamwork.com",
        "verification_method": "create_site",
        "risk_level": "MEDIUM",
        "can_takeover": True
    },
    "kinsta": {
        "cname_patterns": [".kinsta.cloud", ".kinsta.com"],
        "error_patterns": [
            "No site is currently installed here",
            "The site you are looking for could not be found"
        ],
        "claimed_indicators": ["Kinsta"],
        "status_codes": [404],
        "takeover_url": "https://kinsta.com",
        "verification_method": "create_site",
        "risk_level": "HIGH",
        "can_takeover": True
    },
    "agilecrm": {
        "cname_patterns": [".agilecrm.com"],
        "error_patterns": [
            "Sorry, this page is no longer available"
        ],
        "claimed_indicators": ["Agile CRM"],
        "status_codes": [404],
        "takeover_url": "https://www.agilecrm.com",
        "verification_method": "create_portal",
        "risk_level": "MEDIUM",
        "can_takeover": True
    },
    "uptimerobot": {
        "cname_patterns": [".uptimerobot.com", "stats.uptimerobot.com"],
        "error_patterns": [
            "page not found",
            "This public status page is no longer available"
        ],
        "claimed_indicators": ["UptimeRobot"],
        "status_codes": [404],
        "takeover_url": "https://uptimerobot.com",
        "verification_method": "create_status_page",
        "risk_level": "LOW",
        "can_takeover": True
    }
}

# Header-based provider fingerprints (detects provider even when body has no error)
HEADER_FINGERPRINTS = {
    "github": {"Server": "GitHub.com"},
    "heroku": {"Server": "Cowboy", "Via": "vegur"},
    "cloudfront": {"Server": "CloudFront"},
    "fastly": {"X-Served-By": "cache-"},
    "shopify": {"X-Sorting-Hat-ShopId": ""},
    "netlify": {"Server": "Netlify"},
    "vercel": {"Server": "Vercel"},
    "firebase": {"Server": "Google Frontend"},
    "azure": {"Server": "Microsoft-IIS"},
    "s3": {"Server": "AmazonS3"},
    "ghost": {"X-Powered-By": "Express", "X-Cache": "Ghost"},
    "zendesk": {"X-Zendesk-Origin-Server": ""},
}

# Cloud provider IP ranges (CIDR) for dangling A-record detection
# Subset of well-known ranges — full ranges are too large
CLOUD_IP_RANGES = {
    "aws": [
        "52.0.0.0/11", "54.0.0.0/9", "34.192.0.0/12", "18.0.0.0/11",
        "3.0.0.0/9", "13.0.0.0/10", "35.160.0.0/13",
    ],
    "azure": [
        "13.64.0.0/11", "20.0.0.0/10", "40.64.0.0/10",
        "52.224.0.0/11", "104.40.0.0/13",
    ],
    "gcp": [
        "34.64.0.0/10", "35.184.0.0/13", "104.196.0.0/14",
        "130.211.0.0/16", "146.148.0.0/17",
    ],
    "digitalocean": [
        "104.131.0.0/16", "128.199.0.0/16", "139.59.0.0/16",
        "159.65.0.0/16", "167.99.0.0/16", "174.138.0.0/16",
    ],
}
COMMON_SUBDOMAINS = [
    "www", "mail", "web", "blog", "dev", "test", "staging", "api", "mobile", "admin",
    "dashboard", "portal", "ftp", "secure", "vpn", "ssh", "git", "jenkins",
    "nas", "files", "backup", "db", "mysql", "redis", "mongodb",
    "elastic", "kibana", "grafana", "prometheus", "cdn", "static", "assets",
    "img", "images", "media", "shop", "store", "cart", "payment", "billing",
    "account", "auth", "login", "app", "apps", "service", "internal", "intranet",
    "demo", "stage", "prod", "uat", "qa", "beta", "alpha", "search", "docs",
    "wiki", "help", "support", "status", "monitor", "metrics", "analytics",
    "data", "db1", "db2", "sql", "oracle", "postgres", "mariadb", "couchdb",
    "cassandra", "memcached", "rabbitmq", "kafka", "zookeeper", "etcd",
    "consul", "vault", "nomad", "terraform", "packer", "ansible", "puppet",
    "chef", "salt", "jenkins", "bamboo", "teamcity", "gitlab", "bitbucket",
    "gogs", "gitea", "nexus", "artifactory", "sonar", "jira", "confluence",
    "grafana", "prometheus", "alertmanager", "thanos", "cortex", "loki",
    "tempo", "jaeger", "zipkin", "skywalking", "pinpoint", "sentry",
    "logstash", "fluentd", "filebeat", "metricbeat", "packetbeat",
    "heartbeat", "auditbeat", "functionbeat", "journalbeat", "winlogbeat",
    "apm", "rum", "uptime", "maps", "mail2", "smtp", "pop", "pop3", "imap",
    "imap4", "exchange", "owa", "autodiscover", "lync", "lyncdiscover",
    "sip", "meet", "teams", "skype", "webex", "zoom", "gotomeeting",
    "join", "joinme", "appear", "bluejeans", "ringcentral", "cisco",
    "jabber", "xmpp", "irc", "mattermost", "slack", "discord", "rocketchat",
    "zulip", "matrix", "element", "wire", "signal", "telegram", "whatsapp",
    "wechat", "line", "kakao", "viber", "threema", "session", "briar",
    "tox", "retroshare", "jami", "delta", "beta", "gamma", "delta", "epsilon",
    "zeta", "eta", "theta", "iota", "kappa", "lambda", "mu", "nu", "xi",
    "omicron", "pi", "rho", "sigma", "tau", "upsilon", "phi", "chi", "psi",
    "omega", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
    "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"
]

# ============================================================================
# SUBFINDER INTEGRATION MODULE
# ============================================================================

class SubfinderIntegration:
    """Complete Subfinder integration module"""
    
    @staticmethod
    def find_subfinder_binary(custom_path: str = None) -> Optional[str]:
        """Find subfinder binary in system PATH or custom location"""
        if custom_path:
            if os.path.isfile(custom_path) and os.access(custom_path, os.X_OK):
                return custom_path
            path = shutil.which(custom_path)
            if path:
                return path
        
        for binary_name in ["subfinder", "subfinder2", "subfinder3"]:
            path = shutil.which(binary_name)
            if path:
                return path
        
        common_paths = [
            "/usr/local/bin/subfinder",
            "/usr/bin/subfinder",
            "/opt/homebrew/bin/subfinder",
            os.path.expanduser("~/go/bin/subfinder"),
            os.path.expanduser("~/.local/bin/subfinder"),
        ]
        
        for path in common_paths:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path
        
        return None
    
    @staticmethod
    async def run_subfinder(
        domain: str,
        output_file: str,
        binary_path: str = "subfinder",
        extra_args: str = "",
        timeout: int = 300,
        debug: bool = False
    ) -> Tuple[bool, str]:
        """Run subfinder binary"""
        binary = SubfinderIntegration.find_subfinder_binary(binary_path)
        if not binary:
            return False, f"Subfinder binary not found: {binary_path}"
        
        cmd = [binary, "-d", domain, "-silent", "-o", output_file]
        
        if extra_args:
            import shlex
            try:
                extra_args_list = shlex.split(extra_args)
                cmd.extend(extra_args_list)
            except:
                if debug:
                    print(f"[WARNING] Failed to parse extra args: {extra_args}")
        
        default_flags = ["-all", "-recursive"]
        for flag in default_flags:
            if flag not in cmd:
                cmd.append(flag)
        
        if debug:
            print(f"[SUBFINDER] Command: {' '.join(cmd)}")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                if debug:
                    print(f"[SUBFINDER] Success: Found {sum(1 for _ in open(output_file))} subdomains")
                return True, "Success"
            
            if process.returncode != 0:
                error_msg = stderr.decode('utf-8', errors='ignore').strip()
                if debug:
                    print(f"[SUBFINDER] Error (code {process.returncode}): {error_msg}")
                return False, f"Subfinder failed: {error_msg}"
            
            return False, "Subfinder produced no output"
            
        except asyncio.TimeoutError:
            return False, f"Subfinder timeout after {timeout} seconds"
        except FileNotFoundError:
            return False, f"Subfinder binary not found at: {binary}"
        except Exception as e:
            return False, f"Subfinder execution error: {str(e)}"
    
    @staticmethod
    def parse_subfinder_output(file_path: str, domain: str, debug: bool = False) -> Set[str]:
        """Parse subfinder output file"""
        subdomains = set()
        
        if not os.path.exists(file_path):
            return subdomains
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    line = line.split()[0]
                    line = re.sub(r'^https?://', '', line)
                    line = line.split(':')[0]
                    line = line.rstrip('/')
                    line = line.lower().strip()
                    
                    if line.endswith(f".{domain}") or line == domain:
                        subdomains.add(line)
                        if debug and len(subdomains) <= 10:
                            print(f"[SUBFINDER-PARSED] {line}")
            
            if debug:
                print(f"[SUBFINDER] Parsed {len(subdomains)} unique subdomains")
                
        except Exception as e:
            if debug:
                print(f"[SUBFINDER] Parse error: {e}")
        
        return subdomains
    
    @staticmethod
    async def enumerate_with_subfinder(
        domain: str,
        use_subfinder: bool = True,
        subfinder_bin: str = "subfinder",
        subfinder_args: str = "",
        debug: bool = False
    ) -> Set[str]:
        """Main function to enumerate using Subfinder"""
        if not use_subfinder:
            return set()
        
        if COLOR_AVAILABLE:
            print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}🔍 SUBFINDER ENUMERATION{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        else:
            print(f"\n{'='*60}")
            print("🔍 SUBFINDER ENUMERATION")
            print(f"{'='*60}")
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp:
            temp_file = tmp.name
        
        try:
            print(f"[*] Running Subfinder for {domain}...")
            success, message = await SubfinderIntegration.run_subfinder(
                domain=domain,
                output_file=temp_file,
                binary_path=subfinder_bin,
                extra_args=subfinder_args,
                timeout=600,
                debug=debug
            )
            
            if not success:
                if COLOR_AVAILABLE:
                    print(f"{Fore.YELLOW}[!] Subfinder: {message}{Style.RESET_ALL}")
                else:
                    print(f"[!] Subfinder: {message}")
                return set()
            
            subdomains = SubfinderIntegration.parse_subfinder_output(temp_file, domain, debug)
            
            if COLOR_AVAILABLE:
                print(f"{Fore.GREEN}[+] Subfinder found: {len(subdomains)} subdomains{Style.RESET_ALL}")
            else:
                print(f"[+] Subfinder found: {len(subdomains)} subdomains")
            
            if debug and subdomains:
                sample = list(subdomains)[:5]
                print(f"[*] Sample: {', '.join(sample)}")
            
            return subdomains
            
        except Exception as e:
            if COLOR_AVAILABLE:
                print(f"{Fore.RED}[!] Subfinder enumeration failed: {e}{Style.RESET_ALL}")
            else:
                print(f"[!] Subfinder enumeration failed: {e}")
            return set()
        finally:
            try:
                os.unlink(temp_file)
            except:
                pass

# ============================================================================
# DATA MODELS
# ============================================================================

class RiskLevel(Enum):
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFO = auto()
    
class TakeoverStatus(Enum):
    CONFIRMED = "CONFIRMED"
    HIGHLY_LIKELY = "HIGHLY_LIKELY"
    LIKELY = "LIKELY"
    POSSIBLE = "POSSIBLE"
    UNLIKELY = "UNLIKELY"
    SAFE = "SAFE"
    ERROR = "ERROR"

@dataclass
class SubdomainFinding:
    """Complete finding data model with httpx enhancements"""
    subdomain: str
    provider: Optional[str] = None
    cname: Optional[str] = None
    cname_chain: List[str] = field(default_factory=list)
    a_records: List[str] = field(default_factory=list)
    http_status: Optional[int] = None
    https_status: Optional[int] = None
    response_body: Optional[str] = None
    page_title: Optional[str] = None
    response_time: Optional[float] = None
    final_url: Optional[str] = None
    takeover_status: TakeoverStatus = TakeoverStatus.SAFE
    confidence: int = 0
    evidence: List[str] = field(default_factory=list)
    verification_steps: List[str] = field(default_factory=list)
    is_live: bool = False
    risk_level: RiskLevel = RiskLevel.INFO
    timestamp: datetime = field(default_factory=datetime.now)
    wayback_urls: List[str] = field(default_factory=list)
    last_seen: Optional[datetime] = None
    # Advanced takeover detection fields
    ns_records: List[str] = field(default_factory=list)
    ns_takeover: bool = False
    ssl_mismatch: bool = False
    ssl_cert_cn: Optional[str] = None
    dangling_a_record: bool = False
    header_fingerprint: Optional[str] = None
    
    def to_dict(self):
        return {
            "subdomain": self.subdomain,
            "provider": self.provider,
            "cname": self.cname,
            "cname_chain": self.cname_chain,
            "a_records": self.a_records,
            "http_status": self.http_status,
            "https_status": self.https_status,
            "page_title": self.page_title,
            "response_time": self.response_time,
            "final_url": self.final_url,
            "takeover_status": self.takeover_status.value,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "verification_steps": self.verification_steps,
            "is_live": self.is_live,
            "risk_level": self.risk_level.name,
            "timestamp": self.timestamp.isoformat(),
            "wayback_urls": self.wayback_urls,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "ns_records": self.ns_records,
            "ns_takeover": self.ns_takeover,
            "ssl_mismatch": self.ssl_mismatch,
            "ssl_cert_cn": self.ssl_cert_cn,
            "dangling_a_record": self.dangling_a_record,
            "header_fingerprint": self.header_fingerprint
        }

@dataclass
class ScanResult:
    """Overall scan results"""
    domain: str
    timestamp: datetime
    duration: float
    total_subdomains: int
    findings: List[SubdomainFinding]
    statistics: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self):
        return {
            "domain": self.domain,
            "timestamp": self.timestamp.isoformat(),
            "duration": self.duration,
            "total_subdomains": self.total_subdomains,
            "findings": [f.to_dict() for f in self.findings],
            "statistics": self.statistics
        }

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

class ColorPrinter:
    """Colorful console output"""
    _no_color = False  # Class-level flag set from CLI
    
    @staticmethod
    def print(message: str, level: str = "info", color: str = None):
        if not COLOR_AVAILABLE or ColorPrinter._no_color:
            print(f"[{level.upper()}] {message}")
            return
        
        colors = {
            "info": Fore.CYAN,
            "success": Fore.GREEN,
            "warning": Fore.YELLOW,
            "error": Fore.RED,
            "critical": Fore.RED + Style.BRIGHT,
            "debug": Fore.MAGENTA,
        }
        
        color_code = colors.get(level, Fore.WHITE)
        if color:
            color_code = getattr(Fore, color.upper(), Fore.WHITE)
        
        print(f"{color_code}[{level.upper()}] {Style.RESET_ALL}{message}")
    
    @staticmethod
    def print_banner():
        print(BANNER)
    
    @staticmethod
    def print_table(headers: List[str], rows: List[List[str]], title: str = None):
        if RICH_AVAILABLE:
            table = Table(title=title, show_header=True, header_style="bold magenta")
            for header in headers:
                table.add_column(header)
            for row in rows:
                table.add_row(*row)
            Console().print(table)
        else:
            if title:
                print(f"\n{title}")
                print("=" * len(title))
            print(" | ".join(headers))
            print("-" * (sum(len(h) for h in headers) + 3 * (len(headers) - 1)))
            for row in rows:
                print(" | ".join(row))

class RateLimiter:
    """Rate limiting for API calls"""
    def __init__(self, calls_per_second: int = 10):
        self.calls_per_second = calls_per_second
        self.semaphore = asyncio.Semaphore(calls_per_second)
        self.last_call = 0
        self.min_interval = 1.0 / calls_per_second
    
    async def wait(self):
        async with self.semaphore:
            now = time.time()
            elapsed = now - self.last_call
            if elapsed < self.min_interval:
                await asyncio.sleep(self.min_interval - elapsed)
            self.last_call = time.time()

class DNSResolver:
    """Enhanced DNS resolver with dig support and better caching"""
    def __init__(self):
        self.cache = {}
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5
        self.dig_available = shutil.which('dig') is not None
        
        if not self.dig_available and not os.environ.get('SENTINEL_NO_WARN'):
            if COLOR_AVAILABLE:
                print(f"{Fore.YELLOW}[WARNING] dig command not found. CNAME resolution may be limited.")
                print(f"[INFO] Install with: sudo apt-get install dnsutils{Style.RESET_ALL}")
            else:
                print("[WARNING] dig command not found. CNAME resolution may be limited.")
                print("[INFO] Install with: sudo apt-get install dnsutils")
    
    async def resolve_cname(self, domain: str) -> Tuple[Optional[str], List[str]]:
        """Resolve CNAME chain for domain using dig (more reliable)"""
        cache_key = f"cname:{domain}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        # Try using dig first (much more reliable for CNAME chains)
        if self.dig_available:
            try:
                dig_result = await self._resolve_cname_with_dig(domain)
                if dig_result[0]:  # If dig found something
                    self.cache[cache_key] = dig_result
                    return dig_result
            except Exception as e:
                if os.environ.get('SENTINEL_DEBUG'):
                    print(f"[DNS-DEBUG] dig failed for {domain}: {e}")
        
        # Fallback to dnspython
        try:
            answers = await self.resolver.resolve(domain, 'CNAME')
            cname = str(answers[0].target).rstrip('.')
            chain = [cname]
            
            # Follow CNAME chain (max 5 hops to avoid loops)
            for _ in range(5):
                try:
                    next_answers = await self.resolver.resolve(cname, 'CNAME')
                    next_cname = str(next_answers[0].target).rstrip('.')
                    if next_cname in chain:  # Avoid loops
                        break
                    chain.append(next_cname)
                    cname = next_cname
                except:
                    break
            
            result = (chain[0], chain)
            self.cache[cache_key] = result
            return result
        except Exception:
            # Last resort: try direct socket lookup
            try:
                import socket
                # socket.gethostbyname_ex returns (hostname, aliaslist, ipaddrlist)
                result = socket.gethostbyname_ex(domain)
                if result[1]:  # aliaslist contains CNAMEs
                    cname = result[1][0]
                    result = (cname, [cname])
                    self.cache[cache_key] = result
                    return result
            except:
                pass
            
            self.cache[cache_key] = (None, [])
            return (None, [])
    
    async def _resolve_cname_with_dig(self, domain: str) -> Tuple[Optional[str], List[str]]:
        """Resolve CNAME using dig command - more reliable"""
        try:
            # Use dig with +trace for full resolution
            cmd = ['dig', '+short', '+trace', 'CNAME', domain]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=15)
            
            if process.returncode == 0:
                output = stdout.decode('utf-8', errors='ignore').strip()
                if output:
                    # Parse dig output for CNAME records
                    lines = [line.strip() for line in output.split('\n') if line.strip()]
                    cnames = []
                    
                    for line in lines:
                        # Look for CNAME records in dig output
                        if 'CNAME' in line.upper() or '.IN\tCNAME\t' in line:
                            parts = line.split()
                            for i, part in enumerate(parts):
                                if part.upper() == 'CNAME':
                                    if i + 1 < len(parts):
                                        cname = parts[i + 1].rstrip('.')
                                        cnames.append(cname)
                                        break
                    
                    if cnames:
                        # Remove duplicates while preserving order
                        seen = set()
                        unique_cnames = []
                        for cname in cnames:
                            if cname not in seen:
                                seen.add(cname)
                                unique_cnames.append(cname)
                        
                        return (unique_cnames[0], unique_cnames)
            
            # Try simple dig if trace fails
            cmd_simple = ['dig', '+short', 'CNAME', domain]
            process_simple = await asyncio.create_subprocess_exec(
                *cmd_simple,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout_simple, stderr_simple = await asyncio.wait_for(
                process_simple.communicate(), 
                timeout=5
            )
            
            if process_simple.returncode == 0:
                output = stdout_simple.decode('utf-8', errors='ignore').strip()
                if output:
                    cname = output.split('\n')[0].strip().rstrip('.')
                    # Try to follow CNAME chain
                    chain = [cname]
                    for _ in range(5):
                        next_cname = await self._dig_cname_single(cname)
                        if next_cname and next_cname != cname:
                            chain.append(next_cname)
                            cname = next_cname
                        else:
                            break
                    return (chain[0], chain)
                    
        except asyncio.TimeoutError:
            if os.environ.get('SENTINEL_DEBUG'):
                print(f"[DNS-DEBUG] dig timeout for {domain}")
        except Exception as e:
            if os.environ.get('SENTINEL_DEBUG'):
                print(f"[DNS-DEBUG] dig error for {domain}: {e}")
        
        return (None, [])
    
    async def _dig_cname_single(self, domain: str) -> Optional[str]:
        """Get single CNAME using dig"""
        try:
            cmd = ['dig', '+short', 'CNAME', domain]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=5)
            
            if process.returncode == 0:
                output = stdout.decode('utf-8', errors='ignore').strip()
                if output:
                    return output.split('\n')[0].strip().rstrip('.')
        except:
            pass
        return None
    
    async def resolve_a(self, domain: str) -> List[str]:
        """Resolve A records for domain with dig support"""
        cache_key = f"a:{domain}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        # Try dig first
        if self.dig_available:
            try:
                dig_ips = await self._resolve_a_with_dig(domain)
                if dig_ips:
                    self.cache[cache_key] = dig_ips
                    return dig_ips
            except:
                pass
        
        # Fallback to dnspython
        try:
            answers = await self.resolver.resolve(domain, 'A')
            result = [str(r) for r in answers]
            self.cache[cache_key] = result
            return result
        except Exception:
            # Last resort: try socket
            try:
                import socket
                ip = socket.gethostbyname(domain)
                result = [ip]
                self.cache[cache_key] = result
                return result
            except:
                self.cache[cache_key] = []
                return []
    
    async def _resolve_a_with_dig(self, domain: str) -> List[str]:
        """Resolve A records using dig"""
        try:
            cmd = ['dig', '+short', 'A', domain]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=5)
            
            if process.returncode == 0:
                output = stdout.decode('utf-8', errors='ignore').strip()
                if output:
                    ips = []
                    for line in output.split('\n'):
                        ip = line.strip()
                        # Validate IP address format
                        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                            ips.append(ip)
                    return ips
        except:
            pass
        return []
    
    async def check_wildcard(self, domain: str) -> bool:
        """Check if wildcard DNS is configured"""
        random_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=20))
        test_domain = f"{random_str}.{domain}"
        
        try:
            # Check both A and CNAME for wildcard
            a_records = await self.resolve_a(test_domain)
            cname, _ = await self.resolve_cname(test_domain)
            
            # If either exists, it's likely a wildcard
            if len(a_records) > 0 or cname is not None:
                # Double-check with another random domain
                random_str2 = ''.join(random.choices(string.ascii_lowercase + string.digits, k=20))
                test_domain2 = f"{random_str2}.{domain}"
                a2 = await self.resolve_a(test_domain2)
                cname2, _ = await self.resolve_cname(test_domain2)
                
                if len(a2) > 0 or cname2 is not None:
                    return True
        except:
            pass
        
        return False
# ============================================================================
# ENUMERATION ENGINE
# ============================================================================

class SubdomainEnumerator:
    """Multi-source subdomain enumeration"""
    
    def __init__(self, domain: str, rate_limiter: RateLimiter = None, enable_bruteforce: bool = False, wordlist: List[str] = None):
        self.domain = domain
        self.rate_limiter = rate_limiter or RateLimiter()
        self.dns_resolver = DNSResolver()
        self.session = None
        self.enable_bruteforce = enable_bruteforce
        self.wordlist = wordlist or COMMON_SUBDOMAINS
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def enumerate_all(self, sources: List[str] = None) -> Set[str]:
        """Enumerate from all sources"""
        all_subs = set()
        
        if sources is None:
            sources = ["crt_sh", "omnisint", "hackertarget", "wayback"]
        
        ColorPrinter.print(f"Starting enumeration from {len(sources)} sources", "info")
        
        tasks = []
        for source in sources:
            if source == "crt_sh":
                tasks.append(self.enumerate_crtsh())
            elif source == "omnisint":
                tasks.append(self.enumerate_omnisint())
            elif source == "hackertarget":
                tasks.append(self.enumerate_hackertarget())
            elif source == "wayback":
                tasks.append(self.enumerate_wayback())
            elif source == "bruteforce" and self.enable_bruteforce:
                tasks.append(self.enumerate_bruteforce())
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, set):
                all_subs.update(result)
            elif isinstance(result, Exception):
                ColorPrinter.print(f"Enumeration error: {result}", "error")
        
        all_subs.update(self.get_common_subdomains())
        normalized = self.normalize_subdomains(all_subs)
        
        ColorPrinter.print(f"Total unique subdomains found: {len(normalized)}", "success")
        return normalized
    
    async def enumerate_crtsh(self) -> Set[str]:
        """Certificate Transparency enumeration with anti-blocking"""
        subs = set()
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
            'Accept-Language': 'en-US,en;q=0.9',
            'Referer': 'https://crt.sh/'
        }
        
        try:
            await self.rate_limiter.wait()
            async with self.session.get(url, timeout=15, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data:
                        name_value = entry.get('name_value', '')
                        if name_value:
                            for line in name_value.split('\n'):
                                line = line.strip().lower()
                                if line and line.endswith(self.domain):
                                    subs.add(line)
                elif resp.status == 403:
                    ColorPrinter.print("crt.sh blocked request (403). Try manually in browser.", "warning")
                else:
                    ColorPrinter.print(f"crt.sh returned status {resp.status}", "warning")
        except Exception as e:
            ColorPrinter.print(f"crt.sh error: {e}", "warning")
            
            try:
                alt_url = f"https://crt.sh/?q={self.domain}&output=json"
                async with self.session.get(alt_url, timeout=10) as resp2:
                    if resp2.status == 200:
                        text = await resp2.text()
                        import re
                        found_subs = re.findall(r'[a-zA-Z0-9.-]+\.' + re.escape(self.domain), text)
                        subs.update([s.lower() for s in found_subs])
            except:
                pass
        
        return subs
    
    async def enumerate_omnisint(self) -> Set[str]:
        """Omnisint API enumeration"""
        subs = set()
        url = f"https://sonar.omnisint.io/subdomains/{self.domain}"
        
        try:
            await self.rate_limiter.wait()
            async with self.session.get(url, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if isinstance(data, list):
                        for sub in data:
                            full = f"{sub}.{self.domain}"
                            subs.add(full.lower())
        except Exception as e:
            ColorPrinter.print(f"Omnisint error: {e}", "warning")
        
        return subs
    
    async def enumerate_wayback(self) -> Set[str]:
        """Wayback Machine historical URLs"""
        subs = set()
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&fl=original&collapse=urlkey"
        
        try:
            await self.rate_limiter.wait()
            async with self.session.get(url, timeout=15) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for row in data[1:]:
                        if row and row[0]:
                            parsed = urlparse(row[0])
                            if parsed.netloc.endswith(self.domain):
                                subs.add(parsed.netloc.lower())
        except Exception as e:
            ColorPrinter.print(f"Wayback error: {e}", "warning")
        
        return subs
    
    async def enumerate_hackertarget(self) -> Set[str]:
        """HackerTarget API"""
        subs = set()
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        
        try:
            await self.rate_limiter.wait()
            async with self.session.get(url, timeout=10) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    for line in text.splitlines():
                        if ',' in line:
                            sub = line.split(',')[0].strip().lower()
                            if sub.endswith(self.domain):
                                subs.add(sub)
        except Exception as e:
            ColorPrinter.print(f"HackerTarget error: {e}", "warning")
        
        return subs
    
    async def enumerate_bruteforce(self, wordlist: List[str] = None) -> Set[str]:
        """DNS bruteforce enumeration"""
        subs = set()
        
        if wordlist is None:
            wordlist = self.wordlist
        
        ColorPrinter.print(f"Starting brute-force with {len(wordlist)} words...", "info")
        
        # Check for wildcard DNS first
        has_wildcard = await self.dns_resolver.check_wildcard(self.domain)
        if has_wildcard:
            ColorPrinter.print("Warning: Wildcard DNS detected, brute-force may produce false positives", "warning")
        
        # Batch process for efficiency
        batch_size = 50
        for i in range(0, len(wordlist), batch_size):
            batch = wordlist[i:i+batch_size]
            
            tasks = []
            for word in batch:
                subdomain = f"{word}.{self.domain}"
                tasks.append(self.check_subdomain_exists(subdomain))
            
            results = await asyncio.gather(*tasks)
            
            for j, exists in enumerate(results):
                if exists:
                    sub = f"{batch[j]}.{self.domain}"
                    subs.add(sub)
                    if len(subs) % 10 == 0:
                        print(f"[BRUTEFORCE] Found {len(subs)} so far...", end='\r')
        
        if subs:
            print(f"\n[BRUTEFORCE] Found {len(subs)} subdomains")
        
        return subs
    
    async def check_subdomain_exists(self, subdomain: str) -> bool:
        """Check if subdomain exists via DNS"""
        try:
            a_records = await self.dns_resolver.resolve_a(subdomain)
            if a_records:
                return True
            
            cname, _ = await self.dns_resolver.resolve_cname(subdomain)
            if cname:
                return True
        except Exception:
            pass
        
        return False
    
    def get_common_subdomains(self) -> Set[str]:
        """Get common subdomains"""
        common = self.wordlist[:50]  # Use first 50 from wordlist
        return {f"{sub}.{self.domain}" for sub in common}
    
    def normalize_subdomains(self, subdomains: Set[str]) -> Set[str]:
        """Normalize and filter subdomains"""
        normalized = set()
        for sub in subdomains:
            sub = sub.strip().lower()
            if sub.startswith(('http://', 'https://')):
                sub = sub.split('://')[1]
            sub = sub.split(':')[0]
            sub = sub.split('/')[0]
            sub = sub.rstrip('.')
            
            if sub.endswith(self.domain):
                normalized.add(sub)
        
        return normalized

# ============================================================================
# TAKEOVER DETECTION ENGINE
# ============================================================================

class TakeoverDetector:
    """Main takeover detection logic with NXDOMAIN checks and zero false positives"""
    
    def __init__(self, domain: str, args):
        self.domain = domain
        self.args = args
        self.dns_resolver = DNSResolver()
        self.rate_limiter = RateLimiter(calls_per_second=20)
        self.wildcard_cache = {}
        self._wildcard_checked = False
        self._has_wildcard = False
    
    async def check_cname_nxdomain(self, cname: str) -> bool:
        """Check if CNAME target returns NXDOMAIN (strongest takeover signal)"""
        try:
            await self.dns_resolver.resolver.resolve(cname, 'A')
            return False
        except dns.resolver.NXDOMAIN:
            return True
        except dns.resolver.NoAnswer:
            return False
        except dns.resolver.NoNameservers:
            return True  # No nameservers is also a strong signal
        except Exception:
            return False
    
    async def check_wildcard_domain(self) -> bool:
        """Check once if the target domain has wildcard DNS"""
        if self._wildcard_checked:
            return self._has_wildcard
        self._wildcard_checked = True
        self._has_wildcard = await self.dns_resolver.check_wildcard(self.domain)
        if self._has_wildcard and self.args.debug:
            ColorPrinter.print(f"Wildcard DNS detected for {self.domain}, reducing confidence scores", "warning")
        return self._has_wildcard
    
    async def check_ns_takeover(self, subdomain: str) -> Tuple[bool, List[str], List[str]]:
        """Check if NS records for subdomain delegate to dead nameservers.
        Returns (is_vulnerable, ns_records, dead_ns_list)"""
        ns_records = []
        dead_ns = []
        try:
            answers = await self.dns_resolver.resolver.resolve(subdomain, 'NS')
            ns_records = [str(r.target).rstrip('.') for r in answers]
        except dns.resolver.NoAnswer:
            return False, [], []
        except dns.resolver.NXDOMAIN:
            return False, [], []
        except Exception:
            return False, [], []
        
        for ns in ns_records:
            try:
                await self.dns_resolver.resolver.resolve(ns, 'A')
            except dns.resolver.NXDOMAIN:
                dead_ns.append(ns)
            except dns.resolver.NoNameservers:
                dead_ns.append(ns)
            except Exception:
                pass
        
        return len(dead_ns) > 0, ns_records, dead_ns
    
    async def check_chain_nxdomain(self, cname_chain: List[str]) -> List[str]:
        """Walk entire CNAME chain and return any dangling (NXDOMAIN) links"""
        dangling = []
        for link in cname_chain:
            is_nx = await self.check_cname_nxdomain(link)
            if is_nx:
                dangling.append(link)
        return dangling
    
    async def check_ssl_mismatch(self, subdomain: str) -> Tuple[bool, Optional[str]]:
        """Check if SSL cert doesn't match the subdomain (misconfigured resource)"""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            loop = asyncio.get_event_loop()
            # Use a timeout for the SSL connection
            conn = asyncio.open_connection(subdomain, 443, ssl=ctx)
            reader, writer = await asyncio.wait_for(conn, timeout=5.0)
            
            # Get the SSL object from the transport
            ssl_obj = writer.transport.get_extra_info('ssl_object')
            if ssl_obj:
                cert = ssl_obj.getpeercert(binary_form=True)
                if cert:
                    import ssl as ssl_mod
                    decoded = ssl_mod.DER_cert_to_PEM_cert(cert)
                    # Try to get peercert dict
                    try:
                        cert_dict = ssl_obj.getpeercert()
                        if cert_dict:
                            cn = ''
                            sans = []
                            # Extract CN
                            for rdn in cert_dict.get('subject', ()):
                                for attr, value in rdn:
                                    if attr == 'commonName':
                                        cn = value
                            # Extract SANs
                            for san_type, san_value in cert_dict.get('subjectAltName', ()):
                                if san_type == 'DNS':
                                    sans.append(san_value)
                            
                            # Check if subdomain matches CN or any SAN
                            all_names = sans + ([cn] if cn else [])
                            matches = False
                            for name in all_names:
                                if name.startswith('*.'):
                                    # Wildcard match
                                    wildcard_base = name[2:]
                                    if subdomain.endswith(wildcard_base):
                                        matches = True
                                        break
                                elif subdomain == name:
                                    matches = True
                                    break
                            
                            writer.close()
                            try:
                                await writer.wait_closed()
                            except:
                                pass
                            return not matches, cn
                    except:
                        pass
            
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass
        except Exception:
            pass
        return False, None
    
    def check_response_headers(self, headers: dict) -> Optional[str]:
        """Identify provider from HTTP response headers"""
        if not headers:
            return None
        
        for provider, fingerprint in HEADER_FINGERPRINTS.items():
            match_count = 0
            total = len(fingerprint)
            for header_name, expected_value in fingerprint.items():
                actual = headers.get(header_name, '')
                if actual and (not expected_value or expected_value in actual):
                    match_count += 1
            if match_count == total and total > 0:
                return provider
        return None
    
    def check_dangling_a_record(self, a_records: List[str]) -> Tuple[bool, Optional[str]]:
        """Check if A records point to known cloud provider IP ranges"""
        for ip_str in a_records:
            try:
                ip = ipaddress.ip_address(ip_str)
                for provider, ranges in CLOUD_IP_RANGES.items():
                    for cidr in ranges:
                        if ip in ipaddress.ip_network(cidr, strict=False):
                            return True, provider
            except (ValueError, TypeError):
                continue
        return False, None
    
    async def analyze_subdomain(self, subdomain: str) -> SubdomainFinding:
        """Complete analysis of a single subdomain with advanced detection"""
        finding = SubdomainFinding(subdomain=subdomain)
        
        try:
            # Step 1: DNS Analysis
            dns_info = await self.analyze_dns(subdomain)
            finding.cname = dns_info['cname']
            finding.cname_chain = dns_info['cname_chain']
            finding.a_records = dns_info['a_records']
            finding.provider = dns_info['provider']
            
            # Step 2: NS Delegation Check (independent of CNAME)
            ns_vuln, ns_records, dead_ns = await self.check_ns_takeover(subdomain)
            finding.ns_records = ns_records
            finding.ns_takeover = ns_vuln
            if ns_vuln:
                finding.evidence.append(f"🔴 NS TAKEOVER: Dead nameservers detected: {', '.join(dead_ns)}")
            
            # Step 3: Dangling A-Record Check (independent of CNAME)
            if finding.a_records and not finding.cname:
                is_dangling, cloud_provider = self.check_dangling_a_record(finding.a_records)
                finding.dangling_a_record = is_dangling
                if is_dangling:
                    finding.evidence.append(f"⚠️ A-record points to {cloud_provider} IP range — check if IP is still allocated")
            
            # If no CNAME/provider AND no NS takeover AND no dangling A, mark safe and skip
            if not finding.provider and not finding.cname and not ns_vuln and not finding.dangling_a_record:
                finding.takeover_status = TakeoverStatus.SAFE
                finding.evidence.append("No CNAME, NS delegation, or dangling A-record detected")
                return finding
            
            # Step 4: NXDOMAIN Check on CNAME target (strongest signal)
            nxdomain = False
            if finding.cname:
                nxdomain = await self.check_cname_nxdomain(finding.cname)
                if nxdomain:
                    finding.evidence.append(f"CRITICAL: CNAME target '{finding.cname}' returns NXDOMAIN")
            
            # Step 5: Second-order CNAME chain walk
            chain_dangling = []
            if finding.cname_chain and len(finding.cname_chain) > 1:
                chain_dangling = await self.check_chain_nxdomain(finding.cname_chain)
                for link in chain_dangling:
                    if link != finding.cname:  # Avoid duplicate with step 4
                        finding.evidence.append(f"🔴 CHAIN: Intermediate CNAME '{link}' returns NXDOMAIN")
            
            # Step 6: HTTP Analysis with httpx
            http_info = await self.analyze_http(subdomain)
            finding.http_status = http_info.get('http_status')
            finding.https_status = http_info.get('https_status')
            finding.response_body = http_info.get('body', '')
            finding.page_title = http_info.get('page_title', '')
            finding.response_time = http_info.get('response_time')
            finding.final_url = http_info.get('final_url', '')
            finding.is_live = http_info.get('is_live', False)
            
            # Step 7: Header fingerprinting (can identify provider even without CNAME match)
            resp_headers = http_info.get('headers', {})
            header_provider = self.check_response_headers(resp_headers)
            if header_provider:
                finding.header_fingerprint = header_provider
                if not finding.provider:
                    finding.provider = header_provider
                    finding.evidence.append(f"Provider identified via HTTP headers: {header_provider}")
                elif header_provider != finding.provider:
                    finding.evidence.append(f"Header fingerprint ({header_provider}) differs from CNAME provider ({finding.provider})")
            
            # Step 8: SSL Certificate Mismatch
            ssl_mismatch, ssl_cn = await self.check_ssl_mismatch(subdomain)
            finding.ssl_mismatch = ssl_mismatch
            finding.ssl_cert_cn = ssl_cn
            if ssl_mismatch and ssl_cn:
                finding.evidence.append(f"⚠️ SSL mismatch: cert CN='{ssl_cn}' does not match '{subdomain}'")
            
            # Step 9: Dangling A-Record check if CNAME exists (cloud IP behind CNAME)
            if finding.a_records and finding.cname:
                is_dangling, cloud_provider = self.check_dangling_a_record(finding.a_records)
                finding.dangling_a_record = is_dangling
                if is_dangling and not finding.is_live:
                    finding.evidence.append(f"⚠️ CNAME resolves to unreachable {cloud_provider} IP")
            
            # Debug output
            if self.args.debug and finding.is_live:
                response_time_str = f"{finding.response_time:.2f}s" if finding.response_time else "N/A"
                print(f"[DEBUG] {subdomain}: Status={finding.http_status}, "
                      f"Title='{finding.page_title[:30]}', Time={response_time_str}")
            
            # Step 10: Takeover Validation (all signals)
            validation = await self.validate_takeover(
                finding, http_info, nxdomain,
                ns_takeover=ns_vuln, chain_dangling=chain_dangling,
                ssl_mismatch=ssl_mismatch
            )
            
            # Update finding with validation results
            finding.takeover_status = validation['status']
            finding.confidence = validation['confidence']
            finding.evidence.extend(validation['evidence'])
            finding.verification_steps = validation['verification_steps']
            finding.risk_level = validation['risk_level']
            
        except Exception as e:
            finding.takeover_status = TakeoverStatus.ERROR
            finding.evidence.append(f"Analysis error: {str(e)[:100]}")
            if self.args.debug:
                ColorPrinter.print(f"Error analyzing {subdomain}: {e}", "error")
        
        return finding
    
    async def analyze_dns(self, subdomain: str) -> Dict[str, Any]:
        """Analyze DNS records"""
        result = {
            'cname': None,
            'cname_chain': [],
            'a_records': [],
            'provider': None,
            'errors': []
        }
        
        try:
            # Get CNAME chain
            cname, chain = await self.dns_resolver.resolve_cname(subdomain)
            result['cname'] = cname
            result['cname_chain'] = chain
            
            # Get A records
            a_records = await self.dns_resolver.resolve_a(subdomain)
            result['a_records'] = a_records
            
            # Identify provider from CNAME chain
            if cname:
                result['provider'] = self.identify_provider(cname, chain)
            
        except Exception as e:
            result['errors'].append(f"DNS analysis failed: {e}")
        
        return result
    
    def identify_provider(self, cname: str, chain: List[str]) -> Optional[str]:
        """Identify cloud provider from CNAME"""
        if not cname:
            return None
        
        cname_lower = cname.lower()
        for provider, config in PROVIDER_CONFIGS.items():
            for pattern in config['cname_patterns']:
                if pattern.lower() in cname_lower:
                    return provider
        
        # Also check chain
        for link in chain:
            link_lower = link.lower()
            for provider, config in PROVIDER_CONFIGS.items():
                for pattern in config['cname_patterns']:
                    if pattern.lower() in link_lower:
                        return provider
        
        return None
    
    async def analyze_http(self, subdomain: str) -> Dict[str, Any]:
        """HTTP analysis using httpx for better detection"""
        result = {
            'http_status': None,
            'https_status': None,
            'body': '',
            'page_title': '',
            'response_time': None,
            'final_url': '',
            'is_live': False,
            'headers': {},
            'errors': []
        }
        
        urls_to_try = [
            f"http://{subdomain}",
            f"https://{subdomain}"
        ]
        
        http_timeout = getattr(self.args, 'timeout', 10)
        timeout = Timeout(float(http_timeout), connect=5.0)
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        }
        
        try:
            async with AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as client:
                for url in urls_to_try:
                    try:
                        await self.rate_limiter.wait()
                        start_time = time.time()
                        resp = await client.get(url, headers=headers)
                        response_time = time.time() - start_time
                        
                        status_code = resp.status_code
                        final_url = str(resp.url)
                        body = resp.text[:5000]  # Limit body size
                        
                        # Extract title
                        title_match = re.search(r'<title>(.*?)</title>', body, re.IGNORECASE)
                        page_title = title_match.group(1).strip()[:100] if title_match else ""
                        
                        if url.startswith('https://'):
                            result['https_status'] = status_code
                        else:
                            result['http_status'] = status_code
                        
                        result['final_url'] = final_url
                        result['body'] = body
                        result['page_title'] = page_title
                        result['response_time'] = response_time
                        result['is_live'] = True
                        
                        # Capture response headers for fingerprinting
                        result['headers'] = dict(resp.headers)
                        
                        # Break if we got a successful response
                        if status_code < 400:
                            break
                            
                    except Exception as e:
                        result['errors'].append(f"{url}: {str(e)[:100]}")
                        continue
        
        except Exception as e:
            result['errors'].append(f"HTTP client error: {e}")
        
        return result
    
    async def validate_takeover(self, finding: SubdomainFinding, http_info: Dict[str, Any], nxdomain: bool = False,
                                ns_takeover: bool = False, chain_dangling: List[str] = None,
                                ssl_mismatch: bool = False) -> Dict[str, Any]:
        """Validate takeover with multi-signal scoring including NS, chain, SSL checks"""
        validation = {
            'status': TakeoverStatus.UNLIKELY,
            'confidence': 0,
            'evidence': [],
            'verification_steps': [],
            'risk_level': RiskLevel.INFO
        }
        
        if chain_dangling is None:
            chain_dangling = []
        
        # ---- Signal 0: NS Delegation Takeover (+50, highest priority) ----
        if ns_takeover:
            validation['confidence'] += 50
            validation['evidence'].append("🔴 NS DELEGATION: Nameservers return NXDOMAIN — full DNS control possible")
        
        # Handle case where no CNAME provider but NS or dangling A detected
        if not finding.provider and not ns_takeover and not finding.dangling_a_record:
            validation['status'] = TakeoverStatus.SAFE
            validation['evidence'].append("No provider identified")
            return validation
        
        config = PROVIDER_CONFIGS.get(finding.provider, {}) if finding.provider else {}
        
        # Check can_takeover flag — if provider can't actually be taken over, cap confidence
        can_claim = config.get('can_takeover', True)
        
        # Extract error patterns and claimed indicators
        error_patterns = config.get('error_patterns', [])
        claimed_indicators = config.get('claimed_indicators', [])
        expected_status_codes = config.get('status_codes', [404])
        
        # Get best status code
        status_code = finding.https_status or finding.http_status
        response_body = http_info.get('body', '').lower()
        
        # ---- Signal 1: NXDOMAIN (strongest CNAME signal, +40) ----
        if nxdomain:
            validation['confidence'] += 40
            validation['evidence'].append(f"🔴 NXDOMAIN: CNAME target '{finding.cname}' does not exist (strongest takeover signal)")
        elif finding.cname:
            validation['evidence'].append(f"CNAME target '{finding.cname}' resolves (NXDOMAIN not detected)")
        
        # ---- Signal 1b: Second-order CNAME chain (+35 per link) ----
        if chain_dangling:
            validation['confidence'] += min(35 * len(chain_dangling), 70)
            for link in chain_dangling:
                validation['evidence'].append(f"🔴 CHAIN: Intermediate CNAME '{link}' dangling")
        
        # ---- Signal 2: DNS Configuration ----
        if finding.cname:
            validation['evidence'].append(f"CNAME points to: {finding.cname}")
        if finding.provider:
            validation['evidence'].append(f"Provider identified: {finding.provider}")
        
        # ---- Signal 3: HTTP Status Codes (+20) ----
        if status_code in expected_status_codes:
            validation['confidence'] += 20
            validation['evidence'].append(f"Expected HTTP status ({status_code}) found")
        elif status_code is not None:
            validation['evidence'].append(f"HTTP status {status_code} not in expected codes {expected_status_codes}")
        
        # ---- Signal 4: Error Patterns in Response (+30) ----
        error_found = False
        for pattern in error_patterns:
            pattern_lower = pattern.lower()
            if pattern_lower in response_body:
                validation['confidence'] += 30
                validation['evidence'].append(f"Provider error message found: '{pattern}'")
                error_found = True
                break
        
        if not error_found and error_patterns:
            validation['evidence'].append("No provider error messages found")
        
        # ---- Signal 5: No Claimed Indicators (+10) ----
        claimed_found = False
        for indicator in claimed_indicators:
            if indicator.lower() in response_body:
                validation['evidence'].append(f"Site appears claimed (found: '{indicator}')")
                claimed_found = True
                # Reduce confidence — if a site is claimed, takeover is less likely
                validation['confidence'] = max(0, validation['confidence'] - 15)
                break
        
        if not claimed_found and claimed_indicators:
            validation['confidence'] += 10
            validation['evidence'].append("No claimed site indicators found")
        
        # ---- Signal 6: No HTTP response at all (+10 if NXDOMAIN) ----
        if not finding.is_live and nxdomain:
            validation['confidence'] += 10
            validation['evidence'].append("No HTTP response and NXDOMAIN — resource likely unclaimed")
        elif finding.is_live and response_body:
            validation['evidence'].append("Received valid HTTP response")
        else:
            validation['evidence'].append("No valid HTTP response received")
        
        # ---- Signal 7: SSL Certificate Mismatch (+15) ----
        if ssl_mismatch:
            validation['confidence'] += 15
            validation['evidence'].append(f"🟡 SSL cert does not match subdomain (misconfigured resource)")
        
        # ---- Signal 8: Dangling A-Record (+15 if unreachable) ----
        if finding.dangling_a_record and not finding.is_live:
            validation['confidence'] += 15
            validation['evidence'].append("🟡 A-record in cloud IP range and host unreachable")
        
        # ---- Anti-FP: Wildcard suppression ----
        has_wildcard = await self.check_wildcard_domain()
        if has_wildcard:
            validation['confidence'] = max(0, validation['confidence'] - 20)
            validation['evidence'].append("⚠️ Wildcard DNS detected — confidence reduced by 20 to suppress false positives")
        
        # ---- Anti-FP: can_takeover check ----
        if not can_claim and not ns_takeover:
            original_conf = validation['confidence']
            validation['confidence'] = min(validation['confidence'], 30)
            if original_conf > 30:
                validation['evidence'].append(f"⚠️ Provider '{finding.provider}' does not allow arbitrary domain claiming — confidence capped at 30")
        
        # Determine final status
        if validation['confidence'] >= 80:
            validation['status'] = TakeoverStatus.CONFIRMED
            validation['risk_level'] = RiskLevel.CRITICAL
        elif validation['confidence'] >= 60:
            validation['status'] = TakeoverStatus.HIGHLY_LIKELY
            validation['risk_level'] = RiskLevel.HIGH
        elif validation['confidence'] >= 40:
            validation['status'] = TakeoverStatus.LIKELY
            validation['risk_level'] = RiskLevel.MEDIUM
        elif validation['confidence'] >= 20:
            validation['status'] = TakeoverStatus.POSSIBLE
            validation['risk_level'] = RiskLevel.LOW
        elif finding.provider and finding.cname:
            validation['status'] = TakeoverStatus.UNLIKELY
            validation['risk_level'] = RiskLevel.INFO
        else:
            validation['status'] = TakeoverStatus.SAFE
        
        # Add verification steps if potentially vulnerable
        if validation['status'] in [TakeoverStatus.CONFIRMED, TakeoverStatus.HIGHLY_LIKELY, TakeoverStatus.LIKELY]:
            if ns_takeover:
                validation['verification_steps'] = [
                    "1. Register the dead nameserver domain",
                    "2. Set up DNS hosting on the claimed nameserver",
                    f"3. Create DNS records for {finding.subdomain}",
                    "4. Full DNS control achieved — can point to any IP"
                ]
            else:
                validation['verification_steps'] = [
                    f"1. Navigate to {config.get('takeover_url', 'provider console')}",
                    f"2. Create a new {config.get('verification_method', 'resource')}",
                    f"3. Point it to the CNAME: {finding.cname}",
                    f"4. Verify you can access content at http://{finding.subdomain}"
                ]
        
        return validation


# ============================================================================
# REPORT GENERATOR
# ============================================================================

class ReportGenerator:
    """Generate various report formats"""
    
    @staticmethod
    def generate_html_report(scan_result: ScanResult, output_file: str):
        """Generate interactive HTML report with search and filtering"""
        html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SubDomain Sentinel Report - {domain}</title>
    <style>
        * {{ box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background: #0f1117; color: #e1e4e8; }}
        .container {{ max-width: 1500px; margin: 0 auto; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 12px; margin-bottom: 30px; box-shadow: 0 4px 20px rgba(102,126,234,0.3); }}
        .header h1 {{ margin: 0 0 5px 0; font-size: 1.8em; }}
        .header h2 {{ margin: 0 0 10px 0; font-weight: 400; font-size: 1.2em; opacity: 0.9; }}
        .header p {{ margin: 0; opacity: 0.8; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: #161b22; padding: 20px; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.3); text-align: center; border: 1px solid #30363d; }}
        .stat-value {{ font-size: 2.2em; font-weight: bold; color: #58a6ff; }}
        .stat-value.critical {{ color: #f85149; }}
        .stat-value.warning {{ color: #d29922; }}
        .stat-value.vuln {{ color: #f0883e; }}
        .stat-label {{ color: #8b949e; margin-top: 5px; font-size: 0.9em; }}
        .controls {{ margin-bottom: 20px; display: flex; flex-wrap: wrap; gap: 12px; align-items: center; }}
        .search-box {{ padding: 10px 15px; width: 350px; border: 1px solid #30363d; border-radius: 8px; background: #161b22; color: #e1e4e8; font-size: 14px; }}
        .search-box:focus {{ outline: none; border-color: #667eea; box-shadow: 0 0 0 3px rgba(102,126,234,0.2); }}
        .filter-buttons {{ display: flex; flex-wrap: wrap; gap: 8px; }}
        .filter-btn {{ padding: 8px 16px; border: 1px solid #30363d; border-radius: 8px; cursor: pointer; background: #161b22; color: #8b949e; font-size: 13px; transition: all 0.2s; }}
        .filter-btn:hover {{ border-color: #667eea; color: #e1e4e8; }}
        .filter-btn.active {{ background: #667eea; color: white; border-color: #667eea; }}
        table {{ width: 100%; background: #161b22; border-collapse: collapse; border-radius: 12px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.3); border: 1px solid #30363d; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #21262d; font-size: 14px; }}
        th {{ background: #0d1117; font-weight: 600; color: #8b949e; text-transform: uppercase; font-size: 12px; letter-spacing: 0.5px; }}
        tr.main-row:hover {{ background: #1c2128; }}
        .status-confirmed {{ background: rgba(248,81,73,0.15); color: #f85149; padding: 4px 10px; border-radius: 4px; font-weight: 600; font-size: 12px; }}
        .status-highly_likely {{ background: rgba(210,153,34,0.15); color: #d29922; padding: 4px 10px; border-radius: 4px; font-weight: 600; font-size: 12px; }}
        .status-likely {{ background: rgba(56,154,214,0.15); color: #389ad6; padding: 4px 10px; border-radius: 4px; font-weight: 600; font-size: 12px; }}
        .status-possible {{ background: rgba(63,185,80,0.15); color: #3fb950; padding: 4px 10px; border-radius: 4px; font-weight: 600; font-size: 12px; }}
        .status-unlikely {{ background: rgba(139,148,158,0.1); color: #8b949e; padding: 4px 10px; border-radius: 4px; font-weight: 600; font-size: 12px; }}
        .status-safe {{ background: rgba(139,148,158,0.1); color: #8b949e; padding: 4px 10px; border-radius: 4px; font-weight: 600; font-size: 12px; }}
        .status-error {{ background: rgba(248,81,73,0.1); color: #f85149; padding: 4px 10px; border-radius: 4px; font-weight: 600; font-size: 12px; }}
        .risk-critical {{ color: #f85149; font-weight: bold; }}
        .risk-high {{ color: #f0883e; font-weight: bold; }}
        .risk-medium {{ color: #d29922; font-weight: bold; }}
        .risk-low {{ color: #3fb950; font-weight: bold; }}
        .risk-info {{ color: #8b949e; }}
        .toggle-details {{ background: none; border: 1px solid #30363d; color: #58a6ff; cursor: pointer; padding: 5px 12px; border-radius: 6px; font-size: 12px; transition: all 0.2s; }}
        .toggle-details:hover {{ background: rgba(88,166,255,0.1); border-color: #58a6ff; }}
        .details-row {{ background: #0d1117; }}
        .details-content {{ padding: 20px; border-radius: 8px; margin: 5px 0; }}
        .details-content h4 {{ color: #58a6ff; margin: 0 0 15px 0; font-size: 1.1em; }}
        .details-content p {{ margin: 6px 0; color: #c9d1d9; line-height: 1.5; }}
        .details-content strong {{ color: #e1e4e8; }}
        .details-content ul, .details-content ol {{ margin: 5px 0 10px 20px; padding: 0; }}
        .details-content li {{ margin: 4px 0; color: #c9d1d9; line-height: 1.4; }}
        .details-content a {{ color: #58a6ff; text-decoration: none; }}
        .details-content a:hover {{ text-decoration: underline; }}
        .evidence-item {{ padding: 4px 8px; margin: 2px 0; background: rgba(88,166,255,0.05); border-left: 3px solid #30363d; border-radius: 0 4px 4px 0; }}
        .evidence-item.nxdomain {{ border-left-color: #f85149; background: rgba(248,81,73,0.08); }}
        .evidence-item.wildcard {{ border-left-color: #d29922; background: rgba(210,153,34,0.08); }}
        .conf-bar {{ display: inline-block; width: 60px; height: 8px; background: #21262d; border-radius: 4px; overflow: hidden; vertical-align: middle; margin-left: 5px; }}
        .conf-fill {{ height: 100%; border-radius: 4px; }}
        .footer {{ margin-top: 30px; text-align: center; color: #484f58; font-size: 0.85em; padding: 20px; border-top: 1px solid #21262d; }}
        @media print {{
            body {{ background: white; color: #24292e; }}
            .controls, .filter-buttons {{ display: none; }}
            .details-row {{ display: table-row !important; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ SubDomain Sentinel v{VERSION}</h1>
            <h2>Subdomain Takeover Report — {domain}</h2>
            <p>Scan completed: {timestamp} | Duration: {duration_display} seconds</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">{total_subdomains}</div>
                <div class="stat-label">Total Subdomains</div>
            </div>
            <div class="stat-card">
                <div class="stat-value critical">{confirmed}</div>
                <div class="stat-label">Confirmed Takeovers</div>
            </div>
            <div class="stat-card">
                <div class="stat-value warning">{highly_likely}</div>
                <div class="stat-label">Highly Likely</div>
            </div>
            <div class="stat-card">
                <div class="stat-value vuln">{vulnerable}</div>
                <div class="stat-label">Potentially Vulnerable</div>
            </div>
        </div>
        
        <div class="controls">
            <input type="text" id="search" class="search-box" placeholder="Search subdomains, providers, status...">
            <div class="filter-buttons">
                <button class="filter-btn active" data-filter="all">All ({total_subdomains})</button>
                <button class="filter-btn" data-filter="confirmed">Confirmed ({confirmed})</button>
                <button class="filter-btn" data-filter="highly_likely">Highly Likely ({highly_likely})</button>
                <button class="filter-btn" data-filter="vulnerable">Potentially Vulnerable ({vulnerable})</button>
                <button class="filter-btn" data-filter="safe">Safe ({safe})</button>
            </div>
        </div>
        
        <table id="results-table">
            <thead>
                <tr>
                    <th>Subdomain</th>
                    <th>Provider</th>
                    <th>CNAME</th>
                    <th>Status</th>
                    <th>HTTP Status</th>
                    <th>Risk Level</th>
                    <th>Confidence</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                {table_rows}
            </tbody>
        </table>
        
        <div class="footer">
            <p>Generated by SubDomain Sentinel v{VERSION} | {timestamp}</p>
            <p>For security purposes only. Use responsibly.</p>
        </div>
    </div>
    
<script>
(function() {{
    // Toggle details - vanilla JS, no jQuery
    document.addEventListener('click', function(e) {{
        if (e.target.classList.contains('toggle-details')) {{
            var btn = e.target;
            var mainRow = btn.closest('tr.main-row');
            if (!mainRow) return;
            var detailsRow = mainRow.nextElementSibling;
            if (!detailsRow || !detailsRow.classList.contains('details-row')) return;
            var isHidden = detailsRow.style.display === 'none' || detailsRow.style.display === '';
            detailsRow.style.display = isHidden ? 'table-row' : 'none';
            btn.textContent = isHidden ? '\u25bc Hide' : '\u25b6 Details';
        }}
    }});
    // Search
    document.getElementById('search').addEventListener('input', function() {{
        var query = this.value.toLowerCase();
        document.querySelectorAll('tr.main-row').forEach(function(row) {{
            var text = row.textContent.toLowerCase();
            var details = row.nextElementSibling;
            var match = query === '' || text.indexOf(query) > -1;
            row.style.display = match ? '' : 'none';
            if (details && details.classList.contains('details-row')) {{
                details.style.display = 'none';
                var btn = row.querySelector('.toggle-details');
                if (btn) btn.textContent = '\u25b6 Details';
            }}
        }});
    }});
    // Filter
    var filterBtns = document.querySelectorAll('.filter-btn');
    filterBtns.forEach(function(btn) {{
        btn.addEventListener('click', function() {{
            filterBtns.forEach(function(b) {{ b.classList.remove('active'); }});
            btn.classList.add('active');
            var filter = btn.getAttribute('data-filter');
            document.querySelectorAll('tr.main-row').forEach(function(row) {{
                var status = row.getAttribute('data-status');
                var show = false;
                if (filter === 'all') show = true;
                else if (filter === 'confirmed' && status === 'CONFIRMED') show = true;
                else if (filter === 'highly_likely' && status === 'HIGHLY_LIKELY') show = true;
                else if (filter === 'vulnerable' && ['CONFIRMED','HIGHLY_LIKELY','LIKELY','POSSIBLE'].indexOf(status) > -1) show = true;
                else if (filter === 'safe' && (status === 'SAFE' || status === 'UNLIKELY')) show = true;
                row.style.display = show ? '' : 'none';
                var details = row.nextElementSibling;
                if (details && details.classList.contains('details-row')) {{
                    details.style.display = 'none';
                    var tbtn = row.querySelector('.toggle-details');
                    if (tbtn) tbtn.textContent = '\u25b6 Details';
                }}
            }});
        }});
    }});
    // Sort by risk level on load
    var riskOrder = {{'CRITICAL':5, 'HIGH':4, 'MEDIUM':3, 'LOW':2, 'INFO':1}};
    var tbody = document.querySelector('#results-table tbody');
    var mainRows = Array.from(tbody.querySelectorAll('tr.main-row'));
    var pairs = mainRows.map(function(row) {{
        var details = row.nextElementSibling;
        return {{ main: row, details: (details && details.classList.contains('details-row')) ? details : null }};
    }});
    pairs.sort(function(a, b) {{
        var rA = riskOrder[a.main.getAttribute('data-risk')] || 0;
        var rB = riskOrder[b.main.getAttribute('data-risk')] || 0;
        if (rB !== rA) return rB - rA;
        var cA = parseInt(a.main.getAttribute('data-confidence') || '0');
        var cB = parseInt(b.main.getAttribute('data-confidence') || '0');
        return cB - cA;
    }});
    while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
    pairs.forEach(function(pair) {{
        tbody.appendChild(pair.main);
        if (pair.details) tbody.appendChild(pair.details);
    }});
}})();
</script>
</body>
</html>"""
        
        # Calculate statistics
        confirmed = sum(1 for f in scan_result.findings if f.takeover_status == TakeoverStatus.CONFIRMED)
        highly_likely = sum(1 for f in scan_result.findings if f.takeover_status == TakeoverStatus.HIGHLY_LIKELY)
        likely = sum(1 for f in scan_result.findings if f.takeover_status == TakeoverStatus.LIKELY)
        possible = sum(1 for f in scan_result.findings if f.takeover_status == TakeoverStatus.POSSIBLE)
        vulnerable = confirmed + highly_likely + likely + possible
        safe = sum(1 for f in scan_result.findings if f.takeover_status == TakeoverStatus.SAFE)
        
        # Generate table rows
        table_rows = []
        for finding in scan_result.findings:
            status_class = f"status-{finding.takeover_status.value.lower()}"
            risk_class = f"risk-{finding.risk_level.name.lower()}"
            
            # Format CNAME for display
            cname_display = finding.cname[:30] + "..." if finding.cname and len(finding.cname) > 30 else finding.cname
            
            # Confidence bar color
            conf = finding.confidence
            conf_color = '#f85149' if conf >= 80 else '#d29922' if conf >= 40 else '#3fb950' if conf >= 20 else '#8b949e'
            
            # Create main row
            row = f"""
<tr class="main-row" data-status="{finding.takeover_status.value}" data-risk="{finding.risk_level.name}" data-confidence="{finding.confidence}">
    <td><strong>{html.escape(finding.subdomain)}</strong></td>
    <td>{html.escape(finding.provider or 'N/A')}</td>
    <td title="{html.escape(finding.cname or '')}">{html.escape(cname_display or 'N/A')}</td>
    <td><span class="{status_class}">{finding.takeover_status.value}</span></td>
    <td>{finding.http_status or 'N/A'}/{finding.https_status or 'N/A'}</td>
    <td><span class="{risk_class}">{finding.risk_level.name}</span></td>
    <td>{finding.confidence}% <span class="conf-bar"><span class="conf-fill" style="width:{min(conf,100)}%;background:{conf_color}"></span></span></td>
    <td><button class="toggle-details">▶ Details</button></td>
</tr>"""
            
            # Build evidence HTML with color-coded items
            evidence_html = ""
            for e in (finding.evidence[:10] if finding.evidence else []):
                css_class = "evidence-item"
                if "NXDOMAIN" in e:
                    css_class += " nxdomain"
                elif "Wildcard" in e or "wildcard" in e:
                    css_class += " wildcard"
                evidence_html += f'<div class="{css_class}">{html.escape(e)}</div>'
            if not evidence_html:
                evidence_html = '<div class="evidence-item">No evidence collected</div>'
            
            # Create details row
            details = f"""
<tr class="details-row" style="display: none;">
<td colspan="8">
    <div class="details-content">
        <h4>🔍 Detailed Analysis — {html.escape(finding.subdomain)}</h4>
        <p><strong>CNAME Chain:</strong> {html.escape(' → '.join(finding.cname_chain) if finding.cname_chain else 'None')}</p>
        <p><strong>A Records:</strong> {html.escape(', '.join(finding.a_records) if finding.a_records else 'None')}</p>
        <p><strong>NS Records:</strong> {html.escape(', '.join(finding.ns_records) if finding.ns_records else 'None')}</p>
        <p><strong>HTTP Status:</strong> {finding.http_status or 'N/A'} | <strong>HTTPS Status:</strong> {finding.https_status or 'N/A'}</p>
        <p><strong>SSL Cert CN:</strong> {html.escape(finding.ssl_cert_cn or 'N/A')}</p>
        <p><strong>Header Fingerprint:</strong> {html.escape(finding.header_fingerprint or 'None')}</p>
        <p><strong>Page Title:</strong> {html.escape(finding.page_title or 'N/A')}</p>
        <p><strong>Response Time:</strong> {f"{finding.response_time:.2f}s" if finding.response_time is not None else 'N/A'}</p>
        <p><strong>Final URL:</strong> <a href="{html.escape(finding.final_url or '#')}" target="_blank">{html.escape(finding.final_url or 'N/A')}</a></p>
        <p><strong>Evidence ({len(finding.evidence)} signals):</strong></p>
        {evidence_html}
        {('<p><strong>Verification Steps:</strong></p><ol>' + 
          ''.join([f'<li>{html.escape(step)}</li>' for step in finding.verification_steps[:5]]) + 
          '</ol>') if finding.verification_steps else ''}
        <p><strong>Timestamp:</strong> {finding.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
</td>
</tr>"""
            
            table_rows.append(row + details)
        
        # Format duration for display
        duration_display = f"{scan_result.duration:.2f}" if scan_result.duration is not None else "0.00"
        
        # Format the template
        html_content = html_template.format(
            domain=scan_result.domain,
            timestamp=scan_result.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            duration_display=duration_display,
            total_subdomains=scan_result.total_subdomains,
            confirmed=confirmed,
            highly_likely=highly_likely,
            vulnerable=vulnerable,
            safe=safe,
            table_rows=''.join(table_rows),
            VERSION=VERSION
        )
        
        # Write to file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        ColorPrinter.print(f"HTML report generated: {output_file}", "success")
        
    @staticmethod
    def generate_json_report(scan_result: ScanResult, output_file: str):
        """Generate JSON report"""
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(scan_result.to_dict(), f, indent=2, default=str)
        
        ColorPrinter.print(f"JSON report generated: {output_file}", "success")
    
    @staticmethod
    def generate_csv_report(scan_result: ScanResult, output_file: str):
        """Generate CSV report"""
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Subdomain', 'Provider', 'CNAME', 'CNAME Chain', 'A Records',
                'HTTP Status', 'HTTPS Status', 'Page Title', 'Response Time',
                'Takeover Status', 'Confidence %', 'Risk Level', 'Evidence',
                'Is Live', 'Timestamp'
            ])
            
            for finding in scan_result.findings:
                writer.writerow([
                    finding.subdomain,
                    finding.provider or '',
                    finding.cname or '',
                    ' -> '.join(finding.cname_chain),
                    ', '.join(finding.a_records),
                    finding.http_status or '',
                    finding.https_status or '',
                    finding.page_title or '',
                    finding.response_time or '',
                    finding.takeover_status.value,
                    finding.confidence,
                    finding.risk_level.name,
                    ' | '.join(finding.evidence[:3]),
                    finding.is_live,
                    finding.timestamp.strftime('%Y-%m-%d %H:%M:%S')
                ])
        
        ColorPrinter.print(f"CSV report generated: {output_file}", "success")
    
    @staticmethod
    def generate_markdown_report(scan_result: ScanResult, output_file: str):
        """Generate Markdown report"""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"# SubDomain Sentinel Report\n\n")
            f.write(f"**Domain:** {scan_result.domain}\n")
            f.write(f"**Scan Time:** {scan_result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Duration:** {scan_result.duration:.2f} seconds\n")
            f.write(f"**Total Subdomains:** {scan_result.total_subdomains}\n\n")
            
            f.write("## Summary\n\n")
            f.write(f"- ✅ **Safe:** {sum(1 for f in scan_result.findings if f.takeover_status == TakeoverStatus.SAFE)}\n")
            f.write(f"- ⚠️ **Possible:** {sum(1 for f in scan_result.findings if f.takeover_status == TakeoverStatus.POSSIBLE)}\n")
            f.write(f"- 🔥 **Likely:** {sum(1 for f in scan_result.findings if f.takeover_status == TakeoverStatus.LIKELY)}\n")
            f.write(f"- 🚨 **Highly Likely:** {sum(1 for f in scan_result.findings if f.takeover_status == TakeoverStatus.HIGHLY_LIKELY)}\n")
            f.write(f"- 💀 **Confirmed:** {sum(1 for f in scan_result.findings if f.takeover_status == TakeoverStatus.CONFIRMED)}\n\n")
            
            f.write("## Vulnerable Subdomains\n\n")
            f.write("| Subdomain | Provider | CNAME | Status | Risk | Confidence |\n")
            f.write("|-----------|----------|-------|--------|------|------------|\n")
            
            vulnerable_findings = [f for f in scan_result.findings 
                                 if f.takeover_status in [TakeoverStatus.CONFIRMED, TakeoverStatus.HIGHLY_LIKELY, 
                                                         TakeoverStatus.LIKELY, TakeoverStatus.POSSIBLE]]
            
            for finding in sorted(vulnerable_findings, 
                                key=lambda x: (x.confidence, x.risk_level.value), 
                                reverse=True):
                f.write(f"| {finding.subdomain} | {finding.provider or 'N/A'} | {finding.cname[:30] if finding.cname else 'N/A'} | "
                       f"{finding.takeover_status.value} | {finding.risk_level.name} | {finding.confidence}% |\n")
            
            f.write("\n## All Subdomains\n\n")
            f.write("| Subdomain | Provider | Status | Risk |\n")
            f.write("|-----------|----------|--------|------|\n")
            
            for finding in scan_result.findings:
                f.write(f"| {finding.subdomain} | {finding.provider or 'N/A'} | "
                       f"{finding.takeover_status.value} | {finding.risk_level.name} |\n")
        
        ColorPrinter.print(f"Markdown report generated: {output_file}", "success")
    

# ============================================================================
# MAIN SCANNER
# ============================================================================

class SubDomainSentinel:
    """Main scanner class"""
    
    def __init__(self, domain: str, args):
        self.domain = domain
        self.args = args
        self.subdomains = set()
        self.findings = []
        self.start_time = None
        self.end_time = None
        
    async def run(self) -> ScanResult:
        """Main execution flow"""
        self.start_time = time.time()
        
        ColorPrinter.print_banner()
        ColorPrinter.print(f"Starting scan for: {self.domain}", "info")
        
        try:
            # Step 1: Subdomain Enumeration
            self.subdomains = await self.enumerate_subdomains()
            
            if not self.subdomains:
                ColorPrinter.print("No subdomains found!", "error")
                return None
            
            # Step 2: Takeover Analysis
            self.findings = await self.analyze_subdomains()
            
            # Step 3: Generate Reports
            self.end_time = time.time()
            duration = self.end_time - self.start_time
            
            scan_result = ScanResult(
                domain=self.domain,
                timestamp=datetime.now(),
                duration=duration,
                total_subdomains=len(self.subdomains),
                findings=self.findings,
                statistics=self.generate_statistics()
            )
            
            await self.generate_reports(scan_result)
            
            return scan_result
            
        except Exception as e:
            ColorPrinter.print(f"Scanner error: {e}", "error")
            if self.args.debug:
                import traceback
                traceback.print_exc()
            return None
    
    async def enumerate_subdomains(self) -> Set[str]:
        """Enumerate subdomains from all sources"""
        all_subs = set()
        
        # Use Subfinder if enabled
        if self.args.subfinder:
            subfinder_subs = await SubfinderIntegration.enumerate_with_subfinder(
                domain=self.domain,
                use_subfinder=self.args.subfinder,
                subfinder_bin=self.args.subfinder_bin,
                subfinder_args=self.args.subfinder_args,
                debug=self.args.debug
            )
            all_subs.update(subfinder_subs)
        
        # Use built-in enumerator
        if not self.args.subfinder_only:
            async with SubdomainEnumerator(
                domain=self.domain,
                enable_bruteforce=self.args.bruteforce,
                wordlist=self.load_wordlist()
            ) as enumerator:
                enum_subs = await enumerator.enumerate_all()
                all_subs.update(enum_subs)
        
        # Add user-provided subdomains
        if self.args.subdomains_file:
            try:
                with open(self.args.subdomains_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        sub = line.strip().lower()
                        if sub and self.domain in sub:
                            all_subs.add(sub)
            except Exception as e:
                ColorPrinter.print(f"Error reading subdomains file: {e}", "warning")
        
        # Add single subdomain if provided
        if self.args.single_subdomain:
            all_subs.add(self.args.single_subdomain.lower())
        
        return all_subs
    
    def load_wordlist(self) -> List[str]:
        """Load wordlist for brute-force"""
        wordlist = COMMON_SUBDOMAINS.copy()
        
        # Load custom wordlist if provided
        if self.args.wordlist_file:
            try:
                if os.path.exists(self.args.wordlist_file):
                    with open(self.args.wordlist_file, 'r', encoding='utf-8') as f:
                        custom_words = [line.strip() for line in f if line.strip()]
                        wordlist.extend(custom_words)
                        wordlist = list(set(wordlist))  # Remove duplicates
                        ColorPrinter.print(f"Loaded {len(custom_words)} words from wordlist file", "info")
                else:
                    ColorPrinter.print(f"Wordlist file not found: {self.args.wordlist_file}", "warning")
                    ColorPrinter.print("Using built-in wordlist instead", "info")
            except Exception as e:
                ColorPrinter.print(f"Error loading wordlist file: {e}", "warning")
        
        return wordlist
    
    async def analyze_subdomains(self) -> List[SubdomainFinding]:
        """Analyze all subdomains for takeover (concurrent with semaphore)"""
        ColorPrinter.print(f"Analyzing {len(self.subdomains)} subdomains (concurrency: {self.args.threads})...", "info")
        
        detector = TakeoverDetector(self.domain, self.args)
        semaphore = asyncio.Semaphore(self.args.threads)
        completed = [0]
        total = len(self.subdomains)
        
        async def bounded_analyze(subdomain: str) -> SubdomainFinding:
            async with semaphore:
                finding = await detector.analyze_subdomain(subdomain)
                completed[0] += 1
                if not self.args.quiet and completed[0] % 10 == 0:
                    print(f"  Progress: {completed[0]}/{total} ({completed[0]*100//total}%)", end='\r')
                return finding
        
        tasks = [bounded_analyze(sub) for sub in self.subdomains]
        findings = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and convert to list
        valid_findings = []
        for result in findings:
            if isinstance(result, SubdomainFinding):
                valid_findings.append(result)
            elif isinstance(result, Exception):
                if self.args.debug:
                    ColorPrinter.print(f"Analysis exception: {result}", "error")
        
        if not self.args.quiet:
            print(f"  Progress: {total}/{total} (100%)    ")
        
        return valid_findings
    
    def generate_statistics(self) -> Dict[str, Any]:
        """Generate scan statistics"""
        stats = {
            'total_subdomains': len(self.subdomains),
            'live_subdomains': sum(1 for f in self.findings if f.is_live),
            'providers_found': Counter(f.provider for f in self.findings if f.provider),
            'status_distribution': Counter(f.takeover_status.value for f in self.findings),
            'risk_distribution': Counter(f.risk_level.name for f in self.findings),
        }
        
        # Add takeover statistics
        takeover_stats = {
            'confirmed': sum(1 for f in self.findings if f.takeover_status == TakeoverStatus.CONFIRMED),
            'highly_likely': sum(1 for f in self.findings if f.takeover_status == TakeoverStatus.HIGHLY_LIKELY),
            'likely': sum(1 for f in self.findings if f.takeover_status == TakeoverStatus.LIKELY),
            'possible': sum(1 for f in self.findings if f.takeover_status == TakeoverStatus.POSSIBLE),
            'unlikely': sum(1 for f in self.findings if f.takeover_status == TakeoverStatus.UNLIKELY),
            'safe': sum(1 for f in self.findings if f.takeover_status == TakeoverStatus.SAFE),
            'error': sum(1 for f in self.findings if f.takeover_status == TakeoverStatus.ERROR),
        }
        
        stats['takeover_stats'] = takeover_stats
        
        return stats
    
    async def generate_reports(self, scan_result: ScanResult):
        """Generate all requested reports"""
        if not self.args.no_reports:
            base_name = self.args.output or f"sentinel_{self.domain}_{int(time.time())}"
            
            if self.args.html:
                ReportGenerator.generate_html_report(scan_result, f"{base_name}.html")
            
            if self.args.json:
                ReportGenerator.generate_json_report(scan_result, f"{base_name}.json")
            
            if self.args.csv:
                ReportGenerator.generate_csv_report(scan_result, f"{base_name}.csv")
            
            if self.args.markdown:
                ReportGenerator.generate_markdown_report(scan_result, f"{base_name}.md")
            
            # Generate all if no specific format requested
            if not any([self.args.html, self.args.json, self.args.csv, self.args.markdown]):
                ReportGenerator.generate_html_report(scan_result, f"{base_name}.html")
                ReportGenerator.generate_json_report(scan_result, f"{base_name}.json")
                ReportGenerator.generate_csv_report(scan_result, f"{base_name}.csv")
    
    def print_summary(self, scan_result: ScanResult):
        """Print summary to console"""
        if not scan_result:
            return
        
        stats = scan_result.statistics
        takeover_stats = stats.get('takeover_stats', {})
        
        ColorPrinter.print("\n" + "="*60, "info")
        ColorPrinter.print("📊 SCAN SUMMARY", "info")
        ColorPrinter.print("="*60, "info")
        
        print(f"Domain: {self.domain}")
        print(f"Duration: {scan_result.duration:.2f} seconds")
        print(f"Total Subdomains: {len(self.subdomains)}")
        print(f"Live Subdomains: {stats.get('live_subdomains', 0)}")
        
        ColorPrinter.print("\n🔍 TAKEOVER FINDINGS:", "info")
        print(f"  💀 Confirmed: {takeover_stats.get('confirmed', 0)}")
        print(f"  🚨 Highly Likely: {takeover_stats.get('highly_likely', 0)}")
        print(f"  🔥 Likely: {takeover_stats.get('likely', 0)}")
        print(f"  ⚠️ Possible: {takeover_stats.get('possible', 0)}")
        print(f"  ❓ Unlikely: {takeover_stats.get('unlikely', 0)}")
        print(f"  ✅ Safe: {takeover_stats.get('safe', 0)}")
        print(f"  ❌ Errors: {takeover_stats.get('error', 0)}")
        
        # Print confirmed and highly likely findings
        critical_findings = [f for f in scan_result.findings 
                           if f.takeover_status in [TakeoverStatus.CONFIRMED, TakeoverStatus.HIGHLY_LIKELY]]
        
        if critical_findings:
            ColorPrinter.print("\n🚨 CRITICAL FINDINGS:", "critical")
            for finding in critical_findings:
                print(f"  • {finding.subdomain}")
                print(f"    Provider: {finding.provider}")
                print(f"    CNAME: {finding.cname}")
                print(f"    Status: {finding.takeover_status.value}")
                print(f"    Confidence: {finding.confidence}%")
                if finding.verification_steps:
                    print(f"    Next Steps: {finding.verification_steps[0]}")
                print()
        
        # Print provider distribution
        providers = stats.get('providers_found', Counter())
        if providers:
            ColorPrinter.print("\n🏢 PROVIDER DISTRIBUTION:", "info")
            for provider, count in providers.most_common():
                print(f"  {provider}: {count}")
        
        ColorPrinter.print("\n" + "="*60, "info")
        ColorPrinter.print("Scan completed!", "success")
        ColorPrinter.print("="*60, "info")

# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description=f"SubDomain Sentinel v{VERSION} - Enterprise Subdomain Takeover Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  %(prog)s example.com
  %(prog)s example.com --subfinder --html
  %(prog)s example.com --bruteforce --wordlist-file wordlist.txt
  %(prog)s example.com --subfinder-bin /path/to/subfinder --subfinder-args "-t 100"
  %(prog)s example.com --subdomains-file subs.txt --output report
  %(prog)s example.com --single-subdomain test.example.com --debug
  %(prog)s example.com --no-reports --quiet
        """
    )
    
    # Target options
    parser.add_argument("domain", nargs="?", help="Target domain to scan")
    parser.add_argument("--single-subdomain", help="Scan a single subdomain")
    parser.add_argument("--subdomains-file", help="File containing list of subdomains")
    
    # Enumeration options
    parser.add_argument("--subfinder", action="store_true", help="Use Subfinder for enumeration")
    parser.add_argument("--subfinder-only", action="store_true", help="Use ONLY Subfinder (skip built-in enumeration)")
    parser.add_argument("--subfinder-bin", default="subfinder", help="Path to Subfinder binary (default: subfinder)")
    parser.add_argument("--subfinder-args", default="", help="Additional arguments for Subfinder")
    parser.add_argument("--bruteforce", action="store_true", help="Enable DNS brute-force enumeration")
    parser.add_argument("--wordlist-file", help="Custom wordlist file for brute-force")
    
    # Output options
    parser.add_argument("-o", "--output", help="Base name for output files")
    parser.add_argument("--html", action="store_true", help="Generate HTML report")
    parser.add_argument("--json", action="store_true", help="Generate JSON report")
    parser.add_argument("--csv", action="store_true", help="Generate CSV report")
    parser.add_argument("--markdown", action="store_true", help="Generate Markdown report")
    parser.add_argument("--no-reports", action="store_true", help="Don't generate any report files")
    
    # Performance options
    parser.add_argument("-t", "--threads", type=int, default=50, help="Concurrent threads (default: 50)")
    parser.add_argument("--rate-limit", type=int, default=10, help="Requests per second (default: 10)")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP request timeout in seconds (default: 10)")
    
    # Filtering options
    parser.add_argument("--severity-filter", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        default=None, help="Only show findings at or above this severity")
    
    # Other options
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--quiet", action="store_true", help="Suppress non-essential output")
    parser.add_argument("--no-color", action="store_true", help="Disable colored console output")
    parser.add_argument("--version", action="version", version=f"SubDomain Sentinel v{VERSION}")
    
    return parser.parse_args()

def check_dependencies():
    """Check required dependencies"""
    missing = []
    
    # Check Python version
    if sys.version_info < (3, 7):
        print(f"❌ Python 3.7+ required (you have {sys.version_info.major}.{sys.version_info.minor})")
        sys.exit(1)
    
    # Check required modules
    required_modules = [
        ('aiohttp', 'aiohttp'),
        ('httpx', 'httpx'),
        ('dns', 'dnspython'),
        ('tldextract', 'tldextract'),
    ]
    
    for import_name, package_name in required_modules:
        try:
            __import__(import_name)
        except ImportError:
            missing.append(package_name)
    
    if missing:
        print("❌ Missing required packages:")
        for pkg in missing:
            print(f"   - {pkg}")
        print("\nInstall with: pip install " + " ".join(missing))
        sys.exit(1)
    
    # Optional modules warning
    optional_modules = [
        ('rich', 'rich'),
        ('colorama', 'colorama'),
    ]
    
    missing_optional = []
    for import_name, package_name in optional_modules:
        try:
            __import__(import_name)
        except ImportError:
            missing_optional.append(package_name)
    
    if missing_optional:
        print("⚠️ Optional packages missing (enhanced output): " + ", ".join(missing_optional))
        print("   Install with: pip install " + " ".join(missing_optional))

# ============================================================================
# MAIN FUNCTION
# ============================================================================

async def main():
    """Main async function"""
    global args
    args = parse_args()
    
    # Check dependencies
    check_dependencies()
    
    # Wire --no-color flag
    if args.no_color:
        ColorPrinter._no_color = True
    
    # Validate arguments
    if not args.domain and not args.single_subdomain and not args.subdomains_file:
        print("❌ Error: No target specified")
        print("   Provide a domain, single subdomain, or subdomains file")
        print("   Usage: python subsentinal.py <domain> [options]")
        print("   Run with --help for full usage information")
        sys.exit(1)
    
    # Determine target domain
    if args.domain:
        target_domain = args.domain.lower().strip()
    elif args.single_subdomain:
        # Extract domain from subdomain
        parts = args.single_subdomain.lower().split('.')
        if len(parts) >= 2:
            target_domain = '.'.join(parts[-2:])
        else:
            target_domain = args.single_subdomain
    elif args.subdomains_file:
        # Try to extract domain from first line
        try:
            with open(args.subdomains_file, 'r') as f:
                first_line = f.readline().strip().lower()
                parts = first_line.split('.')
                if len(parts) >= 2:
                    target_domain = '.'.join(parts[-2:])
                else:
                    target_domain = "unknown"
        except:
            target_domain = "unknown"
    
    # Initialize and run scanner
    scanner = SubDomainSentinel(target_domain, args)
    scan_result = await scanner.run()
    
    # Print summary
    if scan_result and not args.quiet:
        scanner.print_summary(scan_result)
    
    # Exit with appropriate code
    if scan_result:
        critical_findings = [f for f in scan_result.findings 
                           if f.takeover_status in [TakeoverStatus.CONFIRMED, TakeoverStatus.HIGHLY_LIKELY]]
        
        if critical_findings:
            if COLOR_AVAILABLE:
                print(f"\n{Fore.RED}⚠️  WARNING: {len(critical_findings)} critical findings detected!{Style.RESET_ALL}")
            else:
                print(f"\n⚠️  WARNING: {len(critical_findings)} critical findings detected!")
            sys.exit(2)  # Exit with warning code
        else:
            if COLOR_AVAILABLE:
                print(f"\n{Fore.GREEN}✅ Scan completed successfully{Style.RESET_ALL}")
            else:
                print(f"\n✅ Scan completed successfully")
            sys.exit(0)
    else:
        if COLOR_AVAILABLE:
            print(f"\n{Fore.RED}❌ Scan failed{Style.RESET_ALL}")
        else:
            print(f"\n❌ Scan failed")
        sys.exit(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        if COLOR_AVAILABLE:
            print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        else:
            print(f"\n[!] Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        if COLOR_AVAILABLE:
            print(f"\n{Fore.RED}[!] Unexpected error: {e}{Style.RESET_ALL}")
        else:
            print(f"\n[!] Unexpected error: {e}")
        if args and args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

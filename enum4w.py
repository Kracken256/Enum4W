#!/usr/bin/python3
import sys
import os
from turtle import color
from termcolor import colored
import subprocess
import math


def print_banner():
    print("+=============================================+")
    print("|          " +
          colored("[ ENUM FOR WESLEY SCRIPT ]", "green") + "         |")
    print("|          " +
          colored("[ By Hacker For Hackers! ]", "yellow") + "         |")
    print(
        "| " + colored("[ LEGEL: NO WARENTY; USE AT YOUR OWN RISK ]", "red") + " |")
    print(
        "| " + colored("[ Star this repo on wesleyjones001/Enum4w ]", "green") + " |")
    print("+=============================================+")


def execute_cmd(input: str):
    return subprocess.check_output(input, shell=True, text=True, stderr=subprocess.STDOUT)


def get_users():
    raw = execute_cmd('cut -d ":" -f 1 /etc/passwd')
    users = raw.splitlines()
    return users


def display_users(level: int):
    users = get_users()
    default_users = ["daemon",
                     "bin",
                     "sys",
                     "sync",
                     "games",
                     "man",
                     "lp",
                     "mail",
                     "news",
                     "uucp",
                     "proxy",
                     "backup",
                     "list",
                     "irc",
                     "gnats",
                     "nobody",
                     "_apt",
                     "systemd-network",
                     "systemd-resolve",
                     "systemd-timesync",
                     "messagebus",
                     "tss",
                     "strongswan",
                     "tcpdump",
                     "usbmux",
                     "sshd",
                     "dnsmasq",
                     "avahi",
                     "rtkit",
                     "speech-dispatcher",
                     "nm-openvpn",
                     "nm-openconnect",
                     "lightdm",
                     "pulse",
                     "saned",
                     "colord",
                     "stunnel4",
                     "geoclue",
                     "redsocks",
                     "rwhod",
                     "iodine",
                     "miredo",
                     "statd",
                     "inetsim",
                     "king-phisher",
                     "vboxadd",
                     "ntpsec",
                     "Debian-snmp",
                     "sslh",
                     "_rpc",
                     ]
    print("Users in /etc/passwd: ")
    primary = []
    secondary = []
    for user in users:
        if user in default_users and level == 2:
            secondary.append(colored(user, "blue"))
        elif user not in default_users:
            primary.append(colored(user, "green"))
    l1 = primary + secondary
    if len(l1) > 9:
        for a,b,c in zip(l1[::3],l1[1::3],l1[2::3]):
            print ('{:<30}{:<30}{:<}'.format(a,b,c))
    else:
        print('\n'.join(l1))
    print()
    return

def get_top_processes():
    tmp = execute_cmd("ps au | sort -nrk 3,3 | head -n 10")
    lines = tmp.splitlines()
    return lines

def print_top_processes():
    print("Top 10 processes by CPU usage: ")
    print('\n'.join(get_top_processes()))

def run():
    print_banner()
    args = sys.argv
    enum_level = 1
    if "-c" in args:
        if (args.index("-c")+1) >= len(args):
            print("Specify enum level [ 1-4 ]")
            return
        enum_level = int(args[args.index("-c")+1])

    if enum_level >= 1:
        display_users(enum_level)
    print_top_processes()
    pass


if __name__ == "__main__":
    run()
    exit()

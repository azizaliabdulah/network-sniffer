#!/usr/bin/env python3

# كاتب الأداة: عبدالعزيز علي الأحمري
# الأداة: Packet Sniffer تعليمي
# ⚠️ استخدام تعليمي فقط، تأكد من الأذونات القانونية

import argparse
import os
from scapy.all import sniff, wrpcap
from rich import print
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

def banner():
    console.print(Panel(Text("Simple Packet Sniffer by [bold blue]عبدالعزيز[/bold blue]", justify="center"), 
                   subtitle="Using Scapy + Rich", 
                   subtitle_align="right", 
                   border_style="cyan"))

def check_sudo():
    if os.geteuid() != 0:
        print("[bold red][!] يجب تشغيل الأداة بصلاحيات sudo[/bold red]")
        exit(1)

def handle_packet(pkt):
    global count
    count += 1
    print(f"[bold green][{count}][/bold green] {pkt.summary()}")

def main():
    global count
    count = 0
    banner()
    check_sudo()

    parser = argparse.ArgumentParser(description="🧪 أداة بسيطة لالتقاط الحزم وتخزينها في ملف PCAP")
    parser.add_argument("-i", "--interface", required=True, help="🖧 اسم كرت الشبكة (مثل eth0 أو wlan0)")
    parser.add_argument("-o", "--output", default="capture.pcap", help="💾 اسم ملف الحفظ (افتراضي: capture.pcap)")
    parser.add_argument("-f", "--filter", default="", help="🔍 فلتر BPF (مثال: 'tcp port 80')")
    args = parser.parse_args()

    console.print(f"[bold cyan][+] بدء الالتقاط على:[/bold cyan] {args.interface}")
    if args.filter:
        console.print(f"[bold cyan][+] باستخدام الفلتر:[/bold cyan] '{args.filter}'")

    try:
        sniff(
            iface=args.interface,
            filter=args.filter,
            prn=handle_packet,
            store=True
        )
    except KeyboardInterrupt:
        console.print("\n[bold yellow][!] تم إيقاف الالتقاط من قبل المستخدم.[/bold yellow]")
    except Exception as e:
        console.print(f"[bold red][!] حدث خطأ:[/bold red] {e}")
        return

    if count > 0:
        wrpcap(args.output, sniff(iface=args.interface, filter=args.filter, count=count))
        console.print(f"[bold green][+] تم حفظ {count} حزمة في الملف:[/bold green] {args.output}")
    else:
        console.print("[bold red][!] لم يتم التقاط أي حزم.[/bold red]")

if __name__ == "__main__":
    main()

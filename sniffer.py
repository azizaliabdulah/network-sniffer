#!/usr/bin/env python3

# Packet Sniffer بسيط
# كاتب الأداة: اسمك هنا
# استخدام تعليمي فقط ⚠️

import argparse
from scapy.all import sniff, wrpcap

def main():
    # إعدادات التشغيل
    parser = argparse.ArgumentParser(description="أداة بسيطة لالتقاط الحزم وتخزينها في ملف PCAP")
    parser.add_argument("-i", "--interface", required=True, help="اسم كرت الشبكة، مثل eth0 أو wlan0")
    parser.add_argument("-o", "--output", default="capture.pcap", help="اسم ملف الحفظ (افتراضي capture.pcap)")
    parser.add_argument("-f", "--filter", default="", help="فلتر BPF اختياري مثل: 'tcp port 80'")
    args = parser.parse_args()

    print(f"[+] بدء الالتقاط على: {args.interface}")
    if args.filter:
        print(f"[+] باستخدام الفلتر: {args.filter}")

    try:
        packets = sniff(
            iface=args.interface,
            filter=args.filter,
            prn=lambda pkt: pkt.summary(),
            store=True
        )
    except KeyboardInterrupt:
        print("\n[+] تم إيقاف الالتقاط من قبل المستخدم.")
    except PermissionError:
        print("[!] يجب تشغيل السكربت بصلاحيات sudo.")
        return
    except Exception as e:
        print(f"[!] حدث خطأ: {e}")
        return

    if packets:
        wrpcap(args.output, packets)
        print(f"[+] تم حفظ {len(packets)} حزمة في الملف: {args.output}")
    else:
        print("[!] لم يتم التقاط أي حزم.")

if __name__ == "__main__":
    main()

# special-eureka
جاهيد كايا import argparse
import subprocess
import hashlib
import socket
import base64

def ping_host(host):
    """يقوم بعملية Ping لمضيف معين"""
    try:
        subprocess.run(["ping", "-c", "4", host], check=True)
    except subprocess.CalledProcessError:
        print("فشل في تنفيذ الأمر!")

def scan_ports(host, ports):
    """يفحص المنافذ المفتوحة على مضيف معين"""
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((host, port))
            if result == 0:
                print(f"المنفذ {port} مفتوح")
            else:
                print(f"المنفذ {port} مغلق")

![1000012246](https://github.com/user-attachments/assets/90692cb2-b416-4fe2-b026-c05679192331)

def get_hash(file_path, algo="md5"):
    """يحسب الهاش للملف باستخدام MD5 أو SHA256"""
    hash_func = hashlib.md5() if algo == "md5" else hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                hash_func.update(chunk)
        print(f"{algo.upper()} Hash: {hash_func.hexdigest()}")
    except FileNotFoundError:
        print("الملف غير موجود!")

def dns_lookup(domain):
    """يبحث عن عنوان IP لنطاق معين"""
    try:
        ip = socket.gethostbyname(domain)
        print(f"IP: {ip}")
    except socket.gaierror:
        print("فشل في البحث عن DNS!")

def encode_base64(text):
    """يقوم بتشفير نص إلى Base64"""
    encoded = base64.b64encode(text.encode()).decode()
    print(f"Base64: {encoded}")

def decode_base64(encoded_text):
    """يقوم بفك تشفير Base64"""
    try:
        decoded = base64.b64decode(encoded_text).decode()
        print(f"النص الأصلي: {decoded}")
    except Exception as e:
        print("خطأ في فك التشفير!")

def main():
    parser = argparse.ArgumentParser(description="أداة CLI للأمن السيبراني")
    subparsers = parser.add_subparsers(dest="command")

    # أوامر الشبكة
    parser_ping = subparsers.add_parser("ping", help="تنفيذ Ping على مضيف")
    parser_ping.add_argument("host", help="عنوان IP أو اسم النطاق")

    parser_scan = subparsers.add_parser("scan", help="فحص المنافذ على مضيف")
    parser_scan.add_argument("host", help="عنوان IP")
    parser_scan.add_argument("ports", nargs="+", type=int, help="أرقام المنافذ")

    # أوامر تحليل الملفات
    parser_hash = subparsers.add_parser("hash", help="حساب الهاش لملف")
    parser_hash.add_argument("file", help="مسار الملف")
    parser_hash.add_argument("--algo", choices=["md5", "sha256"], default="md5", help="نوع الهاش (افتراضي MD5)")

    # أوامر DNS
    parser_dns = subparsers.add_parser("dns", help="استعلام عن DNS")
    parser_dns.add_argument("domain", help="اسم النطاق")

    # أوامر التشفير
    parser_encode = subparsers.add_parser("encode", help="تشفير نص إلى Base64")
    parser_encode.add_argument("text", help="النص المراد تشفيره")

    parser_decode = subparsers.add_parser("decode", help="فك تشفير Base64")
    parser_decode.add_argument("encoded_text", help="النص المشفر")

    args = parser.parse_args()

    if args.command == "ping":
        ping_host(args.host)
    elif args.command == "scan":
        scan_ports(args.host, args.ports)
    elif args.command == "hash":
        get_hash(args.file, args.algo)
    elif args.command == "dns":
        dns_lookup(args.domain)
    elif args.command == "encode":
        encode_base64(args.text)
    elif args.command == "decode":
        decode_base64(args.encoded_text)
    else:
        parser.print_help()

if __name__ == "__main__":
    main() 

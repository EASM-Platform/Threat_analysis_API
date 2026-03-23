def build_cpe_candidates(product: str, version:str)-> list[str]:
    candidates = []
    
    if not product or not version:
        return candidates
    
    if product == "Apache httpd":
        candidates.append(f"cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*")
    elif product == "OpenSSH":
        candidates.append(f"cpe:2.3:a:openbsd:openssh:{version}:*:*:*:*:*:*:*")
    elif product == "Werkzeug":
        candidates.append(f"cpe:2.3:a:palletsprojects:werkzeug:{version}:*:*:*:*:*:*:*")
    elif product == "nginx":
        candidates.append(f"cpe:2.3:a:nginx:nginx:{version}:*:*:*:*:*:*:*")
    elif product == "Microsoft IIS":
        candidates.append(f"cpe:2.3:a:microsoft:internet_information_services:{version}:*:*:*:*:*:*:*")

    return candidates
import nmap
import psutil
import socket
# import windows_tools.antivirus
import platform
import sys
import io
import speedtest
import scapy.all as scapy

def leer_html(path):
    with io.open(path, 'r', encoding='utf8') as archivo_html:
        contenido_html = archivo_html.read()
    return contenido_html


def get_local_ip() -> dict:
    """
    Obtiene la dirección IP local del sistema.

    Returns:
        Un diccionario con la dirección IP local del sistema.
    """
    hostname = socket.gethostname()
    IPAddr = socket.gethostbyname(hostname)
    return IPAddr


def get_interface_info() -> dict:
    """
    Obtiene información de las interfaces de red y sus direcciones IP y máscaras de subred.

    Returns:
        Un diccionario donde las claves son los nombres de las interfaces de red y los valores son listas de tuplas
        que contienen las direcciones IP y máscaras de subred de cada interfaz.
    """
    net_ifs = psutil.net_if_addrs()
    result= {'Network Map': ''}
    for interface_name, interface_addresses in net_ifs.items():
        result[interface_name] = []
        for address in interface_addresses:
            if address.family == socket.AF_INET:
                result[interface_name].append({
                    "address": address.address,
                    "netmask": address.netmask
                })
            elif address.family == socket.AF_INET6:
                result[interface_name].append({
                    "address": address.address,
                    "netmask": address.netmask
                })
    return result


def port_scan(ip : str) -> dict:
    """
    Escanea los puertos abiertos en una dirección IP dada.

    Args:
        ip (str): La dirección IP a escanear.

    Returns:
        Un diccionario que contiene los puertos abiertos en la dirección IP dada.
    """

    scanner = nmap.PortScanner()
    scanner.scan(ip)
    result= {'Open Ports': ''}
    for host in scanner.all_hosts():
        if scanner[host].state() == 'up':
            result[host] = []
            for proto in scanner[host].all_protocols():
                lport = scanner[host][proto].keys()
                for port in lport:
                    result[host].append({"port": port, "protocol": proto})
                    
                    if port== 20 or port== 21 and proto=="ftp":
                        result[host].append({"Recommendation": 'The FTP port is insecure, out of date, and can be exploited through anonymous  authentication, cross-site scripting, password brute force, or directory traversal attacks. So it is suggested to keep it closed.'})
                    elif port==22 and proto=="ssh":
                        result[host].append({"Recommendation": 'This port can be exploited by brute forcing SSH credentials or using a private key to gain access to the target system. Therefore it is suggested to keep it closed, as long as its use is not required.'})
                    elif port== 139 or proto== 137 or port== 445 and proto=="tcp":
                        result[host].append({"Recommendation": 'This port could be exploited via the EternalBlue vulnerability, by hacking SMB login credentials, exploiting the SMB port using NTLM Capture, and connecting to SMB using PSexec. So it is suggested to keep it open only when you want to provide shared access to files and printers, through a network.'})
                    elif port== 139 or port== 137 or port== 445 and proto=="udp":
                        result[host].append({"Recommendation": 'This communication protocol could be exploited via the EternalBlue vulnerability, by hacking SMB login credentials, exploiting the SMB port using NTLM Capture, and connecting to SMB using PSexec. So it is suggested to keep it open only when you want to provide shared access to files and printers, through a network.'})
                    elif port== 53 and proto=="tcp" or proto=="udp":
                        result[host].append({"Recommendation": 'This port is used for transfers and queries respectively, making it vulnerable to a distributed denial of service attack. So it is recommended to keep it closed.'})
                    elif port== 80 or port== 8080 and proto=="http":
                        result[host].append({"Recommendation": 'This port is vulnerable to SQL injection, cross-site scripting, cross-site request forgery, and so on. So it is suggested to prefer the HTTPS protocol.'})
                    elif port== 23 and proto=="telnet":
                        result[host].append({"Recommendation": 'This port is outdated, insecure and vulnerable to malware, spoofing, credential sniffing, and credential brute force. So it is suggested to use a more secure port.'})
                    elif port== 25 and proto=="smtp":
                        result[host].append({"Recommendation": 'This port is used to send and receive emails. You can be vulnerable to spam and phishing if you are not well protected.Therefore, it is suggested to use port 587 that supports TLS, to send emails securely.'})
                    elif port==69 and proto=="tftp":
                        result[host].append({"Recommendation": 'This port is used to send and receive files between a user and a server over a network, so it can be compromised through password spraying and unauthorized access, and denial of service attacks. So it is suggested to keep it open only in case it is necessary.'})    
    return result


def get_system_info() -> dict:
    """
    Obtiene información del sistema.

    Returns:
        Un diccionario que contiene la información del sistema.
    """
    def linux_distribution() -> str:
        try:
            return platform.linux_distribution()
        except:
            return 'N/A'
        
    version= platform.release()
    if version =="7" or version=="8" or version=="NT": #Verifica si la versión de Windows está obsoleta
        return {    
            "System Description":'',
            "Python Version": sys.version.split('\n'),
            "Linux Distribution": linux_distribution(),
            "Mac Distribution": platform.mac_ver(),
            "System": platform.system(),
            "Machine": platform.machine(),
            "Platform": platform.platform(),
            "Recommendation":'Your operating system version is out of date, you should update it.',
            "Uname": platform.uname(),
            "Version": platform.version()
        }
    else:
        return {    
            "System Description":'',
            "Python Version": sys.version.split('\n'),
            "Linux Distribution": linux_distribution(),
            "Mac Distribution": platform.mac_ver(),
            "System": platform.system(),
            "Machine": platform.machine(),
            "Platform": platform.platform(),
            "Uname": platform.uname(),
            "Version": platform.version()
        }


# def get_antivirus() -> dict:
#     """
#     Obtiene el software antivirus instalado en el sistema.

#     Returns:
#         Un diccionario que contiene el software antivirus instalado en el sistema.
#     """
    
#     antivirus_info = windows_tools.antivirus.get_installed_antivirus_software()
    
#     if antivirus_info:
#         is_up_to_date = all(av['is_up_to_date'] for av in antivirus_info)
#         if not is_up_to_date:
#             message2 = "Your antivirus is outdated, it is recommended to update it"
#             return {"Antivirus Information": antivirus_info, "Recommendation": message2}
#         else:
#             return antivirus_info
#     else:
#         message = {
#             "Antivirus Software": 'It does not have an antivirus system installed.',
#             "Recommendation": 'You should install an antivirus system on your computer to have real-time protection against virus attacks.',
#             "You can download your antivirus system from the following pages":'',
#             "Avast": 'https://www.avast.com/es-ar/lp-ppc-free-av-brand?ppc_code=012&ppc=a&gad=1&gclid=CjwKCAjwjMiiBhA4EiwAZe6jQ4GHwQoKrQvQFQVzabIjgTmFJL4y4q8gZMx9Kb4CQBM-ZgfyXovpChoC0SIQAvD_BwE&gclsrc=aw.ds#pc',
#             "Avira": 'https://www.avira.com/es/free-antivirus-windows',
#             "Avg Technologies": 'https://www.avg.com/es-ar/ppc/protection-offer-comparison-04?ppc_code=012&ppc=a&gad=1&gclid=CjwKCAjwjMiiBhA4EiwAZe6jQ3vWRkcQL_2dw3ckUml-ACvEgf6EKxSkmpl6aJpLB_UYJHO5YR10JxoClf8QAvD_BwE&gclsrc=aw.ds#pc',
#             "Bitdefender": 'https://www.bitdefender.es/media/html/consumer/new/2020/cl-offer-opt/?pid=60off&cid=ppc|c|google|60off&gclid=CjwKCAjwjMiiBhA4EiwAZe6jQ9MJvJRvFx0Dd6yoJjyb5dstXNs05q-Uug9gAO0jNToByl7jRsX5wRoC5MQQAvD_BwE',
#             "Dr Web": 'https://www.drweb-av.es/',
#             "Eset": 'https://www.eset.com/ar/' ,
#             "F-secure": 'https://www.f-secure.com/es/internet-security',
#             "Mcafee": 'https://www.mcafee.com/consumer/es-cl/landing-page/direct/sem/search-campaign.html?csrc=google&csrcl2=brand&cctype=[ES-CL][Search][Brand]%20Product%20Total%20Protection%20Antivirus&ccstype=&ccoe=direct&ccoel2=sem&pkg_id=521&affid=1485&culture=ES-CL&utm_source=google&utm_medium=SEM&utm_campaign=[ES-CL][Search][Brand]%20Product%20Antivirus&utm_content=[brand][exact]%20mcafee%20antivirus&utm_term=mcafee%20antivirus&gad=1&gclid=CjwKCAjwjMiiBhA4EiwAZe6jQ0nm-dEA7jb0ftwHtijlHom_dhISOBJbvTxHiwDCFLkBOWhhgTtaQBoCbnMQAvD_BwE',
#             "Panda Security": 'https://www.pandasecurity.com/security-promotion/?reg=AR&lang=es&track=99829&campaign=dome2001&option=yearly&coupon=50OFFMULTIP&selector=1&gclid=CjwKCAjwjMiiBhA4EiwAZe6jQzVe2BWnT6kYlAuncd5uf4chPxIDcbNNcinVNAKggnvgU57wutX_YxoCOT8QAvD_BwE',
#             "Trend Micro": 'https://www.trendmicro.com/es_es/forHome/products/free-tools.html',
#             "Malwarebytes": 'https://es.malwarebytes.com/'
#         }
#         return message


def speed_connection() -> dict:
    """
    Devuelve la velocidad de internet en Mbps junto con el ping o latencia
    """
    st = speedtest.Speedtest()
    download_test = st.download() / 10**6 
    upload_test = st.upload() / 10**6
    ping_latency = st.results.ping
    info= {"Internet Speed Information": '',
            "Download internet speed in Mbps" : round(download_test,2),
            "Upload internet speed in Mbps":round(upload_test,2),
            "Ping Latency in ms":round(ping_latency,2)}
    if ping_latency > 100:
        return {"Internet Speed Information": '',
                "Download internet speed in Mbps" : round(download_test,2),
                "Upload internet speed in Mbps":round(upload_test,2),
                "Ping Latency in ms":round(ping_latency,2),
                "Warning": 'High computer latency can affect the ability of security defense systems to effectively detect and prevent threats. It can also increase the risk of errors and failures in data communication.' }
    else:
        return {"Internet Speed Information": '',
                "Download internet speed in Mbps" : round(download_test,2),
                "Upload internet speed in Mbps":round(upload_test,2),
                "Ping Latency in ms":round(ping_latency,2)}
        
              

def user_conect_wifi(ip : str) -> dict:
    direc_ip= ip + "/24"
    solicitud_arp = scapy.ARP(pdst= direc_ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    # Fusionamos
    solicitud_arp_broadcast = broadcast/solicitud_arp
    respuesta = scapy.srp(solicitud_arp_broadcast, timeout=1)[0] # Con esta instrucción le decimos que queremos que pregunte a cada solicitud dentro del router a quién le pertenece dicha ip.
    lista_usuarios = [] # Creamos el diccionario
    for elemento in respuesta:
        usuario = {"IP": elemento[1].psrc, "MAC Address": elemento[1].hwsrc}
        lista_usuarios.append(usuario)
    
    return {"Users connected to wifi": lista_usuarios}
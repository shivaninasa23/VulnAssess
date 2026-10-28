"""Bounded safe discovery and non-crawling HTTP checks."""
import os,re,shutil,subprocess,xml.etree.ElementTree as ET
import requests
import threading
from urllib.parse import urljoin,urlsplit
from .targets import validate_target,validate_redirect,TargetError
from .risk import service_finding,header_findings,normalize_finding
class ScanError(RuntimeError):pass
SCAN_LOCK=threading.BoundedSemaphore(1)
def run_nmap(target,config):
    host,_=validate_target(target,config); binary=config.get("NMAP_PATH","nmap"); exe=binary if os.path.isfile(binary) else shutil.which(binary)
    if not exe:raise ScanError("Nmap is not installed or NMAP_PATH is invalid. Install Nmap and restart the application.")
    ports=config.get("PORTS","22,80,443").strip()
    if not re.fullmatch(r"\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*",ports):raise ScanError("Configured port list is invalid.")
    for part in ports.split(","):
        values=[int(v) for v in part.split("-")]
        if any(v<1 or v>65535 for v in values) or len(values)==2 and (values[0]>values[1] or values[1]-values[0]>1000):raise ScanError("Configured port range is invalid or too broad.")
    cmd=[exe,"-n","-sT","-sV","--version-light","-p",ports,"-oX","-",host]
    try:result=subprocess.run(cmd,capture_output=True,text=True,timeout=min(int(config.get("MAX_SCAN_SECONDS",90)),120),check=False,shell=False)
    except subprocess.TimeoutExpired:raise ScanError("Nmap scan timed out. Reduce the port list or retry later.")
    except OSError:raise ScanError("Nmap could not be started. Check NMAP_PATH and installation.")
    if result.returncode not in (0,1):raise ScanError("Nmap reported a scan error; no results were saved as successful.")
    try:root=ET.fromstring(result.stdout)
    except ET.ParseError:raise ScanError("Nmap returned an unreadable result; assessment marked failed.")
    services=[]
    for h in root.findall("host"):
        address=h.find("address"); hostaddr=address.get("addr") if address is not None else host
        for p in h.findall("./ports/port"):
            state=p.find("state")
            if state is not None and state.get("state")=="open":
                svc=p.find("service"); services.append(dict(host=hostaddr,port=int(p.get("portid")),protocol=p.get("protocol","tcp"),service_name=svc.get("name") if svc is not None else None,product=svc.get("product") if svc is not None else None,version=svc.get("version") if svc is not None else None))
    return services
def run_http(target,config):
    host,scheme=validate_target(target,config,allow_url=True); url=target.strip() if scheme else "https://"+host; https=url.lower().startswith("https://")
    for _ in range(4):
        validate_redirect(url,config)
        try:response=requests.get(url,headers={"User-Agent":"VulnAssess/1.0 (authorized assessment)"},timeout=(3,7),allow_redirects=False,stream=True,verify=True)
        except requests.exceptions.SSLError:
            if https:return [],dict(check_name="HTTPS certificate validation",severity="Medium",confidence="high",rationale="TLS certificate validation failed.",evidence="HTTPS request failed certificate validation.",expected="Use a trusted certificate valid for the hostname.",impact="Clients may not authenticate the server securely.",remediation="Install and renew a valid certificate and verify the hostname and chain.")
            raise ScanError("HTTP request failed.")
        except requests.RequestException:raise ScanError("HTTP request failed or timed out.")
        if response.is_redirect or response.is_permanent_redirect:
            location=response.headers.get("Location"); response.close()
            if not location:break
            url=urljoin(url,location); https=url.lower().startswith("https://"); continue
        headers=dict(response.headers)
        try:
            for chunk in response.iter_content(8192):
                if chunk:break
        finally:response.close()
        break
    else:raise ScanError("Too many HTTP redirects.")
    findings=header_findings(headers,https)
    if https:findings.append(dict(check_name="HTTPS certificate validation",severity="Informational",confidence="high",rationale="The HTTPS endpoint completed a request with standard certificate verification enabled.",evidence="The TLS certificate chain and hostname passed Requests certificate validation.",expected="Keep the certificate trusted, valid, and renewed.",impact="No certificate validation concern was observed in this check.",remediation="Monitor certificate expiry and maintain the trusted certificate chain."))
    return findings,None

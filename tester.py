import asyncio 
import base64 
import json 
import os 
import random 
import socket 
import tempfile 
import time 
import urllib .parse 
from dataclasses import dataclass 
from typing import Optional ,Tuple 

import aiohttp 


@dataclass 
class TestResult :
    ok :bool 
    latency_ms :Optional [int ]=None 
    exit_ip :Optional [str ]=None 
    ok_count :int =0 
    tries :int =1 





def flag_emoji_from_cc (country_code :str )->str :
    cc =(country_code or "").strip ().upper ()
    if len (cc )!=2 or not cc .isalpha ():
        return "🏳️"
    return chr (0x1F1E6 +(ord (cc [0 ])-ord ("A")))+chr (0x1F1E6 +(ord (cc [1 ])-ord ("A")))


def grade_from_latency (latency_ms :int ,good_ms :int ,ok_ms :int )->str :
    if latency_ms <=good_ms :
        return "AA"
    if latency_ms <=ok_ms :
        return "BB"
    return "CC"


def grade_label (code :str )->Tuple [str ,str ]:
    code =(code or "").upper ()
    if code =="AA":
        return "🟢","Turbo"
    if code =="BB":
        return "🟡","OK"
    return "🔴","Meh"


def url_encode_name (name :str )->str :
    return urllib .parse .quote (name ,safe ="")


def _safe_json_dumps (obj )->str :
    return json .dumps (obj ,ensure_ascii =False ,separators =(",",":"),sort_keys =True )





def normalize_config_for_fp (raw :str )->str :
    raw =(raw or "").strip ()
    if raw .startswith (("vless://","trojan://","ss://")):
        return raw .split ("#",1 )[0 ]
    if raw .startswith ("vmess://"):
        b64s =raw [len ("vmess://"):].strip ()
        b64s =b64s .replace ("-","+").replace ("_","/")
        try :
            pad ="="*(-len (b64s )%4 )
            data =base64 .b64decode (b64s +pad )
            j =json .loads (data .decode ("utf-8",errors ="ignore"))
            if isinstance (j ,dict ):
                j ["ps"]=""
                out =base64 .b64encode (_safe_json_dumps (j ).encode ("utf-8")).decode ("utf-8")
                return "vmess://"+out 
        except Exception :
            return raw 
    return raw 


def apply_rename (raw :str ,new_name :str )->str :
    raw =(raw or "").strip ()
    if raw .startswith (("vless://","trojan://","ss://")):
        base =raw .split ("#",1 )[0 ]
        return f"{base}#{url_encode_name(new_name)}"

    if raw .startswith ("vmess://"):
        b64s =raw [len ("vmess://"):].strip ()
        b64s =b64s .replace ("-","+").replace ("_","/")
        try :
            pad ="="*(-len (b64s )%4 )
            data =base64 .b64decode (b64s +pad )
            j =json .loads (data .decode ("utf-8",errors ="ignore"))
            if isinstance (j ,dict ):
                j ["ps"]=new_name 
                out =base64 .b64encode (_safe_json_dumps (j ).encode ("utf-8")).decode ("utf-8")
                return "vmess://"+out 
        except Exception :
            pass 
        return raw .split ("#",1 )[0 ]+f"#{url_encode_name(new_name)}"

    return raw 





def _pick_free_port ()->int :
    s =socket .socket (socket .AF_INET ,socket .SOCK_STREAM )
    s .bind (("127.0.0.1",0 ))
    port =s .getsockname ()[1 ]
    s .close ()
    return port 


def pick_socks_port ()->int :
    for _ in range (20 ):
        p =random .randint (20000 ,45000 )
        with socket .socket (socket .AF_INET ,socket .SOCK_STREAM )as s :
            try :
                s .bind (("127.0.0.1",p ))
                return p 
            except OSError :
                continue 
    return _pick_free_port ()





async def geoip_ipapi_full (
ip :str ,timeout_sec :int =6 
)->Tuple [Optional [str ],Optional [str ],Optional [str ],Optional [str ]]:
    """
    returns: (countryCode, country, as, org)
    """
    url =f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,as,org,isp"
    timeout =aiohttp .ClientTimeout (total =timeout_sec )
    async with aiohttp .ClientSession (timeout =timeout )as session :
        async with session .get (url )as resp :
            j =await resp .json (content_type =None )
            if j .get ("status")=="success":
                cc =j .get ("countryCode")
                country =j .get ("country")
                asn =j .get ("as")
                org =j .get ("org")or j .get ("isp")
                return cc ,country ,asn ,org 
    return None ,None ,None ,None 





async def _curl_ip (
curl_bin :str ,
socks_port :int ,
timeout_sec :int ,
)->Tuple [Optional [str ],Optional [int ]]:
    """
    returns (ip, latency_ms)
    """
    t0 =time .perf_counter ()
    curl =await asyncio .create_subprocess_exec (
    curl_bin ,
    "-sS",
    "--max-time",
    str (timeout_sec ),
    "--socks5-hostname",
    f"127.0.0.1:{socks_port}",
    "https://api.ipify.org?format=json",
    stdout =asyncio .subprocess .PIPE ,
    stderr =asyncio .subprocess .DEVNULL ,
    )
    out ,_ =await curl .communicate ()
    dt_ms =int ((time .perf_counter ()-t0 )*1000 )

    if curl .returncode !=0 :
        return None ,dt_ms 

    try :
        data =json .loads (out .decode ("utf-8",errors ="ignore"))
        ip =data .get ("ip")
        return (str (ip )if ip else None ),dt_ms 
    except Exception :
        return None ,dt_ms 


async def run_xray_test (
xray_bin :str ,
xray_config :dict ,
timeout_sec :int ,
curl_bin :str ="curl",
tries :int =3 ,
delay_ms :int =250 ,
do_ip_check :bool =True ,
do_latency :bool =True ,
)->TestResult :

    socks_port =xray_config ["inbounds"][0 ]["port"]
    tries =max (1 ,int (tries ))

    with tempfile .TemporaryDirectory (prefix ="mdma_xray_")as td :
        cfg_path =os .path .join (td ,"config.json")
        with open (cfg_path ,"w",encoding ="utf-8")as f :
            json .dump (xray_config ,f ,ensure_ascii =False )

        proc =await asyncio .create_subprocess_exec (
        xray_bin ,
        "run",
        "-c",
        cfg_path ,
        stdout =asyncio .subprocess .DEVNULL ,
        stderr =asyncio .subprocess .DEVNULL ,
        )

        try :
            await asyncio .sleep (0.35 )

            ok_count =0 
            best_latency :Optional [int ]=None 
            last_ip :Optional [str ]=None 

            for i in range (tries ):
                if not do_ip_check :
                    if proc .returncode is None :
                        ok_count +=1 
                    if i <tries -1 :
                        await asyncio .sleep (delay_ms /1000 )
                    continue 

                ip ,dt_ms =await _curl_ip (curl_bin ,socks_port ,timeout_sec )

                if ip :
                    ok_count +=1 
                    last_ip =ip 
                    if do_latency :
                        if best_latency is None or dt_ms <best_latency :
                            best_latency =dt_ms 

                if i <tries -1 :
                    await asyncio .sleep (delay_ms /1000 )

            if ok_count <=0 :
                return TestResult (ok =False ,latency_ms =best_latency ,exit_ip =last_ip ,ok_count =ok_count ,tries =tries )

            latency_out =best_latency if (do_latency and best_latency is not None )else (best_latency or 0 )

            return TestResult (ok =True ,latency_ms =latency_out ,exit_ip =last_ip ,ok_count =ok_count ,tries =tries )

        finally :
            if proc .returncode is None :
                proc .terminate ()
                try :
                    await asyncio .wait_for (proc .wait (),timeout =2.0 )
                except asyncio .TimeoutError :
                    proc .kill ()

import asyncio 
import hashlib 
import html 
import json 
import logging 
import re 
import time 
import urllib .parse 
from dataclasses import dataclass 
from typing import Dict ,List ,Optional 

from telethon import TelegramClient ,events 
from telethon .errors import FloodWaitError 
from telethon .tl .types import MessageEntityTextUrl ,MessageEntityUrl 

from db import DB 
from tester import (
TestResult ,
apply_rename ,
flag_emoji_from_cc ,
geoip_ipapi_full ,
grade_from_latency ,
grade_label ,
normalize_config_for_fp ,
pick_socks_port ,
run_xray_test ,
)




RE_LINK =re .compile (r"(vless://[^\s]+|vmess://[^\s]+|trojan://[^\s]+|ss://[^\s]+)",re .IGNORECASE )
ZERO_WIDTH =["\u200b","\u200c","\u200d","\ufeff"]

TRIM_CHARS =" \t\r\n>)]}.,؛،"


def sha1 (s :str )->str :
    return hashlib .sha1 (s .encode ("utf-8",errors ="ignore")).hexdigest ()


def proto_of (link :str )->str :
    link =(link or "").strip ().lower ()
    for p in ("vless","vmess","trojan","ss"):
        if link .startswith (p +"://"):
            return p 
    return "unknown"


def clean_text (s :str )->str :
    if not s :
        return ""
    for z in ZERO_WIDTH :
        s =s .replace (z ,"")
    return s 


def clean_link (link :str )->str :
    link =clean_text (link or "")
    link =link .strip (TRIM_CHARS )
    link =link .replace ("\n","").replace ("\r","").strip ()
    return link 


def extract_links_from_message (msg )->List [str ]:

    out :List [str ]=[]
    raw =clean_text (getattr (msg ,"raw_text","")or "")


    ents =getattr (msg ,"entities",None )or []
    for e in ents :
        try :
            if isinstance (e ,MessageEntityTextUrl )and e .url :
                u =clean_link (e .url )
                if u :
                    out .append (u )
            elif isinstance (e ,MessageEntityUrl ):
                u =raw [e .offset :e .offset +e .length ]
                u =clean_link (u )
                if u :
                    out .append (u )
        except Exception :
            continue 


    for m in RE_LINK .finditer (raw ):
        u =clean_link (m .group (1 ))
        if u :
            out .append (u )


    seen =set ()
    final =[]
    for u in out :
        k =u .lower ()
        if k not in seen :
            seen .add (k )
            final .append (u )
    return final 





def detect_security_from_link (link :str )->str :

    p =proto_of (link )
    if p in ("vless","trojan"):
        base =link .split ("#",1 )[0 ]
        u =urllib .parse .urlparse (base )
        qs =urllib .parse .parse_qs (u .query )
        sec =(qs .get ("security",["none"])[0 ]or "none").lower ()
        if sec =="tls":
            return "TLS"
        if sec =="reality":
            return "REALITY"
        return "PLAIN"

    if p =="vmess":
        import base64 

        b64 =link [len ("vmess://"):].strip ()
        b64 =b64 .replace ("-","+").replace ("_","/")
        try :
            pad ="="*(-len (b64 )%4 )
            raw =base64 .b64decode (b64 +pad )
            j =json .loads (raw .decode ("utf-8",errors ="ignore"))
            tls =(j .get ("tls")or "").lower ()
            return "TLS"if tls else "PLAIN"
        except Exception :
            return "PLAIN"

    return "PLAIN"


def build_outbound_from_link (link :str )->Dict :
    """
    Robust enough for the common share links:
    - vless / trojan (ws/tcp, tls/reality/none)
    - vmess (base64 json)
    - ss (3 patterns)
    """
    p =proto_of (link )


    if p in ("vless","trojan"):
        base =link .split ("#",1 )[0 ]
        u =urllib .parse .urlparse (base )

        userinfo ,hostport =u .netloc .split ("@",1 )if "@"in u .netloc else ("",u .netloc )
        if ":"not in hostport :
            raise ValueError ("Missing host:port")
        host ,port_s =hostport .rsplit (":",1 )
        port =int (port_s )

        qs =urllib .parse .parse_qs (u .query )
        security =(qs .get ("security",["none"])[0 ]or "none").lower ()
        sni =qs .get ("sni",[None ])[0 ]or qs .get ("host",[None ])[0 ]
        fp =qs .get ("fp",[None ])[0 ]
        net =(qs .get ("type",["tcp"])[0 ]or "tcp").lower ()
        path =qs .get ("path",["/"])[0 ]
        host_hdr =qs .get ("host",[None ])[0 ]
        alpn =qs .get ("alpn",[None ])[0 ]
        pbk =qs .get ("pbk",[None ])[0 ]
        sid =qs .get ("sid",[None ])[0 ]
        spx =qs .get ("spx",[None ])[0 ]

        sec ="tls"if security =="tls"else ("reality"if security =="reality"else "none")

        if p =="vless":
            out :Dict ={
            "protocol":"vless",
            "settings":{
            "vnext":[
            {
            "address":host ,
            "port":port ,
            "users":[{"id":(userinfo or u .username or ""),"encryption":"none"}],
            }
            ]
            },
            "streamSettings":{"network":net ,"security":sec },
            }
        else :
            out ={
            "protocol":"trojan",
            "settings":{
            "servers":[{"address":host ,"port":port ,"password":(userinfo or u .username or "")}]
            },
            "streamSettings":{"network":net ,"security":sec },
            }

        if sec in ("tls","reality"):
            tls_settings ={}
            if sni :
                tls_settings ["serverName"]=sni 
            if alpn :
                tls_settings ["alpn"]=[a .strip ()for a in alpn .split (",")if a .strip ()]
            if fp :
                tls_settings ["fingerprint"]=fp 

            if sec =="tls":
                out ["streamSettings"]["tlsSettings"]=tls_settings or {}
            else :
                reality =tls_settings or {}
                if pbk :
                    reality ["publicKey"]=pbk 
                if sid :
                    reality ["shortId"]=sid 
                if spx :
                    reality ["spiderX"]=spx 
                out ["streamSettings"]["realitySettings"]=reality 

        if net =="ws":
            ws ={"path":path }
            if host_hdr :
                ws ["headers"]={"Host":host_hdr }
            out ["streamSettings"]["wsSettings"]=ws 

        return out 


    if p =="vmess":
        import base64 

        b64 =link [len ("vmess://"):].strip ()
        b64 =b64 .replace ("-","+").replace ("_","/")
        try :
            pad ="="*(-len (b64 )%4 )
            raw =base64 .b64decode (b64 +pad )
            j =json .loads (raw .decode ("utf-8",errors ="ignore"))
        except Exception :
            raise ValueError ("Invalid vmess base64/json")

        addr =j .get ("add")
        port =int (j .get ("port"))
        uuid =j .get ("id")
        aid =int (j .get ("aid",0 ))
        net =(j .get ("net")or "tcp").lower ()
        tls =(j .get ("tls")or "").lower ()
        host_hdr =j .get ("host")or None 
        path =j .get ("path")or "/"
        sni =j .get ("sni")or j .get ("host")or None 

        out :Dict ={
        "protocol":"vmess",
        "settings":{
        "vnext":[
        {"address":addr ,"port":port ,"users":[{"id":uuid ,"alterId":aid ,"security":"auto"}]}
        ]
        },
        "streamSettings":{"network":net ,"security":"tls"if tls else "none"},
        }

        if tls :
            out ["streamSettings"]["tlsSettings"]={"serverName":sni }if sni else {}

        if net =="ws":
            ws ={"path":path }
            if host_hdr :
                ws ["headers"]={"Host":host_hdr }
            out ["streamSettings"]["wsSettings"]=ws 

        return out 


    if p =="ss":
        import base64 

        base =link .split ("#",1 )[0 ].strip ()
        u =urllib .parse .urlparse (base )

        def b64decode_urlsafe (s :str )->str :
            s =s .strip ().replace ("-","+").replace ("_","/")
            pad ="="*(-len (s )%4 )
            return base64 .b64decode (s +pad ).decode ("utf-8",errors ="ignore")

        host =port =method =password =None 


        if u .netloc and "@"in u .netloc :
            left ,hostport =u .netloc .split ("@",1 )
            if ":"in left and ":"in hostport :
                try :
                    method ,password =left .split (":",1 )
                    host ,port_s =hostport .rsplit (":",1 )
                    port =int (port_s )
                except Exception :
                    pass 


        if not (host and port and method and password )and u .netloc and "@"in u .netloc :
            left ,hostport =u .netloc .split ("@",1 )
            try :
                decoded =b64decode_urlsafe (left )
                if ":"in decoded and ":"in hostport :
                    method ,password =decoded .split (":",1 )
                    host ,port_s =hostport .rsplit (":",1 )
                    port =int (port_s )
            except Exception :
                pass 


        if not (host and port and method and password ):
            blob =(u .netloc or u .path or "").replace ("ss://","").strip ("/")
            blob =blob .split ("?",1 )[0 ]
            try :
                decoded =b64decode_urlsafe (blob )
                if "@"in decoded :
                    userinfo ,hostport =decoded .split ("@",1 )
                    if ":"in userinfo and ":"in hostport :
                        method ,password =userinfo .split (":",1 )
                        host ,port_s =hostport .rsplit (":",1 )
                        port =int (port_s )
            except Exception :
                pass 

        if not (host and port and method and password ):
            raise ValueError ("Unsupported ss:// format")

        return {
        "protocol":"shadowsocks",
        "settings":{"servers":[{"address":host ,"port":port ,"method":method ,"password":password }]},
        "streamSettings":{"network":"tcp","security":"none"},
        }

    raise ValueError (f"Unsupported or unknown protocol link: {p}")


def build_xray_test_config (outbound :Dict ,socks_port :int )->Dict :
    return {
    "log":{"loglevel":"none"},
    "inbounds":[
    {"listen":"127.0.0.1","port":socks_port ,"protocol":"socks","settings":{"udp":True }}
    ],
    "outbounds":[
    outbound ,
    {"protocol":"freedom","tag":"direct"},
    {"protocol":"blackhole","tag":"block"},
    ],
    "routing":{"domainStrategy":"AsIs"},
    }


def _h (s :str )->str :

    return html .escape (s or "",quote =False )


async def safe_send_html (client :TelegramClient ,target :str ,text_html :str )->None :
    """
    Robust send:
    - FloodWait handling
    - falls back to plain text if HTML parse fails
    - avoids worker crash
    """
    while True :
        try :
            await client .send_message (target ,text_html ,parse_mode ="html")
            return 
        except FloodWaitError as e :
            await asyncio .sleep (int (e .seconds )+1 )
        except Exception :

            try :
                await client .send_message (target ,re .sub (r"<[^>]+>","",text_html ),parse_mode =None )
                return 
            except FloodWaitError as e :
                await asyncio .sleep (int (e .seconds )+1 )





@dataclass 
class Job :
    raw_link :str 
    source :str 
    msg_id :int 


class CircuitBreaker :
    def __init__ (self ,fail_threshold :int ,cool_down_sec :int ):
        self .fail_threshold =fail_threshold 
        self .cool_down_sec =cool_down_sec 
        self .fail_count =0 
        self .paused_until =0.0 

    def on_success (self ):
        self .fail_count =0 

    def on_fail (self ):
        self .fail_count +=1 
        if self .fail_count >=self .fail_threshold :
            self .paused_until =time .time ()+self .cool_down_sec 
            self .fail_count =0 

    def is_paused (self )->bool :
        return time .time ()<self .paused_until 

    def remaining (self )->int :
        return max (0 ,int (self .paused_until -time .time ()))

    def state (self )->dict :
        return {
        "paused":self .is_paused (),
        "remaining_sec":self .remaining (),
        "fail_threshold":self .fail_threshold ,
        "cool_down_sec":self .cool_down_sec ,
        }


def render_post_html (
renamed_link :str ,
flag :str ,
country :str ,
proto :str ,
security_label :str ,
latency_ms :int ,
grade_code :str ,
ok_count :int ,
tries :int ,
asn :Optional [str ],
org :Optional [str ],
fixed_caption :str ,
add_tags :bool =True ,
gold_pick :bool =False ,
)->str :

    grade_emo ,grade_name =grade_label (grade_code )
    proto_u =(proto or "").upper ()
    country_s =country or "Unknown"

    gold ="⭐️ <b>Gold pick</b>\n"if gold_pick else ""
    asn_line =""
    if asn or org :
        if asn and org :
            asn_line =f"🏢 ASN: <code>{_h(org)}</code> (<code>{_h(asn)}</code>)\n"
        elif asn :
            asn_line =f"🏢 ASN: <code>{_h(asn)}</code>\n"
        else :
            asn_line =f"🏢 ASN: <code>{_h(org or '')}</code>\n"

    tags =""
    if add_tags :
        tags =f"\n#{proto.lower()} #{security_label.lower()} #{grade_code.lower()}"


    fixed =_h (fixed_caption or "")

    msg =(
    f"<code>{_h(renamed_link)}</code>\n\n"
    f"{_h(flag)} {_h(country_s)} • {_h(proto_u)} • {_h(security_label)} • {_h(grade_emo)} <b>{_h(grade_name)}</b>\n"
    f"{gold}"
    f"⚡ Ping: <code>{latency_ms}ms</code> • Stability: <code>{ok_count}/{tries}</code>\n"
    f"{asn_line}"
    f"{_h(tags)}"
    f"{fixed}"
    )


    if len (msg )>3900 :

        msg2 =msg .replace (_h (tags ),"")
        if len (msg2 )<=3900 :
            return msg2 

        short_fixed =(_h (fixed_caption or ""))[:300 ]
        msg3 =(
        f"<code>{_h(renamed_link)}</code>\n\n"
        f"{_h(flag)} {_h(country_s)} • {_h(proto_u)} • {_h(security_label)} • {_h(grade_emo)} <b>{_h(grade_name)}</b>\n"
        f"{gold}"
        f"⚡ Ping: <code>{latency_ms}ms</code> • Stability: <code>{ok_count}/{tries}</code>\n"
        f"{asn_line}"
        f"{short_fixed}"
        )
        return msg3 [:3900 ]

    return msg 


async def main ()->None :
    with open ("config.json","r",encoding ="utf-8")as f :
        file_cfg =json .load (f )

    logging .basicConfig (level =getattr (logging ,file_cfg .get ("logging",{}).get ("level","INFO")))
    log =logging .getLogger ("mdma-bot")


    db =DB (file_cfg .get ("db_path","bot.db"))

    runtime_cfg =db .get_settings_dict ()or {}
    cfg ={**file_cfg ,**runtime_cfg }
    for k in ("filters","xray","caption","geoip","telegram","panel"):
        if isinstance (file_cfg .get (k ),dict )or isinstance (runtime_cfg .get (k ),dict ):
            merged ={}
            merged .update (file_cfg .get (k ,{})or {})
            merged .update (runtime_cfg .get (k ,{})or {})
            cfg [k ]=merged 

    api_id =int (cfg ["telegram"]["api_id"])
    api_hash =cfg ["telegram"]["api_hash"]
    session_name =cfg ["telegram"]["session_name"]

    sources =[s .strip ()for s in cfg ["sources"]]
    sources_set =set (s .lower ()for s in sources )
    target_channel =cfg ["target_channel"]

    fixed_caption =(cfg .get ("caption",{})or {}).get ("fixed","\n\n—\n⚠️MDMA")
    rename_text =cfg .get ("rename_text","MDMA")

    filters =cfg ["filters"]
    enabled =set (p .lower ()for p in filters .get ("enabled_protocols",["vless","vmess","trojan","ss"]))
    test_timeout =int (filters .get ("test_timeout_sec",8 ))
    good_ms =int (filters .get ("good_ms",300 ))
    ok_ms =int (filters .get ("ok_ms",900 ))
    dedupe_hours =int (filters .get ("dedupe_window_hours",24 ))

    stability_tries =int (filters .get ("stability_tries",3 ))
    stability_delay_ms =int (filters .get ("stability_delay_ms",250 ))

    post_interval_sec =int (cfg .get ("post_interval_sec",10 ))

    gold_ping_ms =int (filters .get ("gold_ping_ms",150 ))
    gold_need =int (filters .get ("gold_need_ok",3 ))

    switches =cfg .get ("switches",{})or {}
    enable_testing =bool (switches .get ("enable_testing",True ))
    enable_geoip =bool (switches .get ("enable_geoip",True ))
    enable_send =bool (switches .get ("enable_send",True ))
    enable_ip_check =bool (switches .get ("enable_ip_check",True ))
    enable_latency =bool (switches .get ("enable_latency",True ))

    xray_bin =cfg ["xray"]["binary_path"]
    curl_bin =(cfg .get ("curl",{})or {}).get ("binary_path","curl")

    geoip_timeout =int ((cfg .get ("geoip",{})or {}).get ("timeout_sec",6 ))

    worker_count =int (filters .get ("worker_count",1 ))
    max_queue =int (filters .get ("max_queue",1000 ))

    cb_fail_threshold =int (filters .get ("cb_fail_threshold",30 ))
    cb_cooldown_sec =int (filters .get ("cb_cooldown_sec",60 ))
    breaker =CircuitBreaker (cb_fail_threshold ,cb_cooldown_sec )

    client =TelegramClient (session_name ,api_id ,api_hash )
    await client .start ()
    me =await client .get_me ()
    log .info ("Logged in as: %s (id=%s)",getattr (me ,"username",None ),me .id )
    log .info ("Listening on sources: %s",sources )
    log .info ("Workers: %s | testing=%s geoip=%s send=%s",worker_count ,enable_testing ,enable_geoip ,enable_send )

    q :asyncio .Queue [Job ]=asyncio .Queue (maxsize =max_queue )
    sem =asyncio .Semaphore (worker_count )

    async def heartbeat_loop ():
        while True :
            try :
                meta ={
                "queue":q .qsize (),
                "max_queue":max_queue ,
                "workers":worker_count ,
                "breaker":breaker .state (),
                "switches":{
                "enable_testing":enable_testing ,
                "enable_geoip":enable_geoip ,
                "enable_send":enable_send ,
                "enable_ip_check":enable_ip_check ,
                "enable_latency":enable_latency ,
                },
                "target":target_channel ,
                "sources":sources ,
                }
                db .set_health ("bot","ok",meta )
            except Exception :
                pass 
            await asyncio .sleep (15 )

    asyncio .create_task (heartbeat_loop ())

    async def enqueue_job (job :Job ):
        if q .full ():
            log .warning ("Queue full; dropping job from %s msg=%s",job .source ,job .msg_id )
            db .add_event (kind ="drop_queue_full",source =job .source ,msg_id =job .msg_id ,detail ="queue_full")
            return 
        await q .put (job )
        db .add_event (kind ="enqueue",source =job .source ,msg_id =job .msg_id ,detail ="enqueued")

    @client .on (events .NewMessage (chats =sources ))
    async def handler (event :events .NewMessage .Event )->None :
        chat =await event .get_chat ()
        username =(getattr (chat ,"username",None )or "").lower ()
        if not username or ("@"+username )not in sources_set :
            return 

        links =extract_links_from_message (event .message )
        if not links :
            return 

        src ="@"+username 
        log .info ("New message from %s | msg_id=%s | links=%d",src ,event .message .id ,len (links ))
        db .add_event (kind ="rx",source =src ,msg_id =event .message .id ,detail =f"links={len(links)}")

        for raw_link in links :
            await enqueue_job (Job (raw_link =raw_link ,source =src ,msg_id =event .message .id ))

    async def process_job (job :Job ):
        nonlocal enable_testing ,enable_geoip ,enable_send ,enable_ip_check ,enable_latency 

        runtime_cfg2 =db .get_settings_dict ()or {}
        if runtime_cfg2 :
            sw2 =runtime_cfg2 .get ("switches")or {}
            enable_testing =bool (sw2 .get ("enable_testing",enable_testing ))
            enable_geoip =bool (sw2 .get ("enable_geoip",enable_geoip ))
            enable_send =bool (sw2 .get ("enable_send",enable_send ))
            enable_ip_check =bool (sw2 .get ("enable_ip_check",enable_ip_check ))
            enable_latency =bool (sw2 .get ("enable_latency",enable_latency ))

        raw_link =clean_link (job .raw_link )
        p =proto_of (raw_link )
        if p not in enabled :
            db .add_event (kind ="skip_proto",source =job .source ,msg_id =job .msg_id ,proto =p ,detail ="disabled_proto")
            return 

        norm =normalize_config_for_fp (raw_link )
        fp =sha1 (norm )
        db .touch_seen (fp )

        if db .recently_posted (fp ,dedupe_hours ):
            db .add_event (kind ="dedupe_skip",source =job .source ,msg_id =job .msg_id ,fp =fp ,proto =p ,detail ="recently_posted")
            return 

        try :
            outbound =build_outbound_from_link (raw_link )
        except Exception as e :
            db .set_test_result (fp ,"skip",None ,None ,None ,None ,None ,None )
            db .add_event (kind ="parse_fail",source =job .source ,msg_id =job .msg_id ,fp =fp ,proto =p ,status ="skip",detail =str (e ))
            log .warning ("Skip unparseable (%s): %s",p ,e )
            return 

        if breaker .is_paused ():
            db .add_event (kind ="cb_paused_skip",source =job .source ,msg_id =job .msg_id ,fp =fp ,proto =p ,detail =f"remaining={breaker.remaining()}")
            log .warning ("Circuit paused (%ss). Skipping tests temporarily.",breaker .remaining ())
            return 

        socks_port =pick_socks_port ()
        xcfg =build_xray_test_config (outbound ,socks_port )

        if not enable_testing :
            db .set_test_result (fp ,"ok",None ,None ,None ,None ,None ,None )
            db .add_event (kind ="test_bypassed",source =job .source ,msg_id =job .msg_id ,fp =fp ,proto =p ,status ="ok",detail ="enable_testing=false")
            return 

        tries =max (1 ,stability_tries )
        try :
            res =await run_xray_test (
            xray_bin =xray_bin ,
            xray_config =xcfg ,
            timeout_sec =test_timeout ,
            curl_bin =curl_bin ,
            tries =tries ,
            delay_ms =stability_delay_ms ,
            do_ip_check =enable_ip_check ,
            do_latency =enable_latency ,
            )
        except Exception as e :
            breaker .on_fail ()
            db .set_test_result (fp ,"fail",None ,None ,None ,None ,None ,None )
            db .add_event (kind ="test_crash",source =job .source ,msg_id =job .msg_id ,fp =fp ,proto =p ,status ="fail",detail =str (e ))
            log .exception ("Test crashed: %s",e )
            return 

        if not res .ok :
            breaker .on_fail ()
            db .set_test_result (fp ,"fail",res .latency_ms ,res .exit_ip ,None ,None ,None ,None )
            db .add_event (
            kind ="test",
            source =job .source ,
            msg_id =job .msg_id ,
            fp =fp ,
            proto =p ,
            status ="fail",
            latency_ms =res .latency_ms ,
            exit_ip =res .exit_ip ,
            detail =json .dumps ({"ok_count":res .ok_count ,"tries":res .tries },ensure_ascii =False ),
            )
            return 

        breaker .on_success ()

        cc =country =asn =org =None 
        if enable_geoip and res .exit_ip :
            try :
                cc ,country ,asn ,org =await geoip_ipapi_full (res .exit_ip ,timeout_sec =geoip_timeout )
            except Exception :
                cc ,country ,asn ,org =None ,None ,None ,None 

        flag =flag_emoji_from_cc (cc or "")
        security_label =detect_security_from_link (raw_link )

        latency_ms =int (res .latency_ms or 999999 )
        grade_code =grade_from_latency (latency_ms ,good_ms ,ok_ms )

        gold_pick =(latency_ms <=gold_ping_ms )and (res .ok_count >=gold_need )and (res .tries >=gold_need )

        star ="⭐️ "if gold_pick else ""
        new_name =f"{star}{flag} {rename_text} {grade_code}".strip ()
        renamed_link =apply_rename (raw_link ,new_name )

        db .set_test_result (fp ,"ok",latency_ms ,res .exit_ip ,cc ,country ,asn ,org )
        db .add_event (
        kind ="test",
        source =job .source ,
        msg_id =job .msg_id ,
        fp =fp ,
        proto =p ,
        status ="ok",
        latency_ms =latency_ms ,
        exit_ip =res .exit_ip ,
        country_code =cc ,
        country =country ,
        asn =asn ,
        org =org ,
        detail =json .dumps ({"ok_count":res .ok_count ,"tries":res .tries ,"grade":grade_code ,"security":security_label },ensure_ascii =False ),
        )

        if not enable_send :
            db .add_event (kind ="send_bypassed",source =job .source ,msg_id =job .msg_id ,fp =fp ,proto =p ,status ="ok",detail ="enable_send=false")
            return 

        msg =render_post_html (
        renamed_link =renamed_link ,
        flag =flag ,
        country =country or (cc or "Unknown"),
        proto =p ,
        security_label =security_label ,
        latency_ms =latency_ms ,
        grade_code =grade_code ,
        ok_count =res .ok_count ,
        tries =res .tries ,
        asn =asn ,
        org =org ,
        fixed_caption =fixed_caption ,
        add_tags =True ,
        gold_pick =gold_pick ,
        )

        await safe_send_html (client ,target_channel ,msg )
        db .mark_posted (fp )
        db .add_event (kind ="posted",source =job .source ,msg_id =job .msg_id ,fp =fp ,proto =p ,status ="ok",latency_ms =latency_ms ,exit_ip =res .exit_ip ,country_code =cc ,country =country ,asn =asn ,org =org ,detail ="posted")

        await asyncio .sleep (post_interval_sec )

    async def worker_loop (i :int ):
        wlog =logging .getLogger ("mdma-bot")
        wlog .info ("Worker-%d started",i )
        while True :
            job =await q .get ()
            try :
                async with sem :
                    await process_job (job )
            except Exception as e :
                wlog .exception ("Worker-%d error: %s",i ,e )
                db .add_event (kind ="worker_error",source =job .source ,msg_id =job .msg_id ,detail =str (e ))
            finally :
                q .task_done ()

    for i in range (worker_count ):
        asyncio .create_task (worker_loop (i +1 ))

    await client .run_until_disconnected ()


if __name__ =="__main__":
    asyncio .run (main ())

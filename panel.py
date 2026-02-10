import json 
import time 
from datetime import datetime 

import pandas as pd 
import streamlit as st 

from db import DB 


def must_login (username :str ,password :str )->None :
    st .session_state .setdefault ("authed",False )

    if st .session_state ["authed"]:
        return 

    st .title ("MDMA Bot Panel")

    u =st .text_input ("Username")
    p =st .text_input ("Password",type ="password")
    if st .button ("Login"):
        if u ==username and p ==password :
            st .session_state ["authed"]=True 
            st .rerun ()
        else :
            st .error ("Wrong username/password")

    st .stop ()


def _load_cfg ()->dict :
    with open ("config.json","r",encoding ="utf-8")as f :
        return json .load (f )


def _ts_to_str (ts :int )->str :
    try :
        return datetime .fromtimestamp (int (ts )).strftime ("%Y-%m-%d %H:%M:%S")
    except Exception :
        return str (ts )


@st .cache_data (ttl =3 )
def _cached_kpis (db_path :str ,hours :int )->dict :
    return DB (db_path ).get_kpis (hours =hours )


@st .cache_data (ttl =3 )
def _cached_series (db_path :str ,hours :int ,kind :str )->pd .DataFrame :
    rows =DB (db_path ).get_timeseries (hours =hours ,kind =kind )
    if not rows :
        return pd .DataFrame ({"time":[],"count":[]})
    df =pd .DataFrame (rows )
    df ["time"]=df ["ts"].apply (_ts_to_str )
    return df [["time","count"]]


@st .cache_data (ttl =3 )
def _cached_events (db_path :str ,limit :int )->pd .DataFrame :
    rows =DB (db_path ).get_events (limit =limit )
    df =pd .DataFrame (rows )
    if not df .empty :
        df ["time"]=df ["ts"].apply (_ts_to_str )
    return df 


@st .cache_data (ttl =3 )
def _cached_top_countries (db_path :str ,hours :int )->pd .DataFrame :
    rows =DB (db_path ).get_top_countries (hours =hours ,limit =12 )
    return pd .DataFrame (rows )


@st .cache_data (ttl =3 )
def _cached_top_asn (db_path :str ,hours :int )->pd .DataFrame :
    rows =DB (db_path ).get_top_asn (hours =hours ,limit =12 )
    return pd .DataFrame (rows )


def page_dashboard (db :DB ,db_path :str ,window_hours :int ):
    st .subheader ("Dashboard")

    k =_cached_kpis (db_path ,window_hours )

    c1 ,c2 ,c3 ,c4 ,c5 =st .columns (5 )
    c1 .metric ("RX (msgs)",k .get ("rx",0 ))
    c2 .metric ("Posted",k .get ("posted",0 ))
    c3 .metric ("Test OK",k .get ("test_ok",0 ))
    c4 .metric ("Test FAIL",k .get ("test_fail",0 ))
    c5 .metric ("Avg Latency",f"{k['avg_latency_ms']} ms"if k .get ("avg_latency_ms")is not None else "—")

    st .divider ()

    left ,right =st .columns ([2 ,1 ])

    with left :
        st .caption ("Time-series (per hour)")
        df_posted =_cached_series (db_path ,hours =min (168 ,window_hours *2 ),kind ="posted")
        st .line_chart (df_posted .set_index ("time"))

        df_test_ok =_cached_series (db_path ,hours =min (168 ,window_hours *2 ),kind ="test")

        st .line_chart (df_test_ok .set_index ("time"))

    with right :
        st .caption ("Top Countries (OK tests)")
        tc =_cached_top_countries (db_path ,window_hours )
        if tc .empty :
            st .info ("No data yet.")
        else :
            st .dataframe (tc ,use_container_width =True ,hide_index =True )

        st .caption ("Top ASN / Org (OK tests)")
        ta =_cached_top_asn (db_path ,window_hours )
        if ta .empty :
            st .info ("No data yet.")
        else :
            st .dataframe (ta ,use_container_width =True ,hide_index =True )

    st .divider ()
    st .caption ("Health")
    health =db .get_health_all ()
    if not health :
        st .info ("No health records yet.")
    else :
        for h in health :
            meta =h .get ("meta")or {}
            st .write (
            f"**{h['component']}** — `{h['status']}` — last: `{_ts_to_str(h['updated_ts'])}`"
            )
            if meta :
                st .json (meta ,expanded =False )

    st .divider ()
    st .caption ("Latest events")
    ev =_cached_events (db_path ,limit =200 )
    if ev .empty :
        st .info ("No events yet.")
    else :
        st .dataframe (
        ev [["time","kind","status","proto","source","msg_id","latency_ms","country_code","country","org","detail"]],
        use_container_width =True ,
        hide_index =True ,
        )


def page_settings (cfg_file :dict ,db :DB ):
    st .subheader ("Settings (Live switches + Safe configs)")

    current =db .get_settings_dict ()or {}

    defaults ={
    "switches":{
    "enable_testing":True ,
    "enable_ip_check":True ,
    "enable_latency":True ,
    "enable_geoip":True ,
    "enable_send":True ,
    },
    "filters":{
    "stability_tries":3 ,
    "stability_delay_ms":250 ,
    "worker_count":1 ,
    "max_queue":1000 ,
    "cb_fail_threshold":30 ,
    "cb_cooldown_sec":60 ,
    "gold_ping_ms":150 ,
    "gold_need_ok":3 ,
    },
    "rename_text":cfg_file .get ("rename_text","MDMA"),
    "post_interval_sec":cfg_file .get ("post_interval_sec",10 ),
    "caption":cfg_file .get ("caption",{}),
    "geoip":cfg_file .get ("geoip",{}),
    "xray":cfg_file .get ("xray",{}),
    "curl":cfg_file .get ("curl",{}),
    "sources":cfg_file .get ("sources",[]),
    "target_channel":cfg_file .get ("target_channel",""),
    }

    merged ={}
    merged .update (defaults )
    merged .update (current )

    tabs =st .tabs (["Switches","Testing","Workers/Safety","Gold ⭐","Posting","Channels","Binaries","Caption","Raw JSON"])

    with tabs [0 ]:
        sw =merged .get ("switches",{})
        sw ["enable_testing"]=st .toggle ("Enable Testing",value =bool (sw .get ("enable_testing",True )))
        sw ["enable_ip_check"]=st .toggle ("Enable IP Check (ipify)",value =bool (sw .get ("enable_ip_check",True )))
        sw ["enable_latency"]=st .toggle ("Enable Latency",value =bool (sw .get ("enable_latency",True )))
        sw ["enable_geoip"]=st .toggle ("Enable GeoIP + ASN",value =bool (sw .get ("enable_geoip",True )))
        sw ["enable_send"]=st .toggle ("Enable Send to Target",value =bool (sw .get ("enable_send",True )))
        merged ["switches"]=sw 

    with tabs [1 ]:
        f =merged .get ("filters",{})
        f ["stability_tries"]=st .slider ("Stability tries",1 ,5 ,int (f .get ("stability_tries",3 )))
        f ["stability_delay_ms"]=st .slider ("Delay between tries (ms)",0 ,2000 ,int (f .get ("stability_delay_ms",250 )))
        merged ["filters"]=f 

    with tabs [2 ]:
        f =merged .get ("filters",{})
        f ["worker_count"]=st .slider ("Workers (parallel tests)",1 ,5 ,int (f .get ("worker_count",1 )))
        f ["max_queue"]=st .slider ("Max Queue",100 ,5000 ,int (f .get ("max_queue",1000 )))
        f ["cb_fail_threshold"]=st .slider ("Circuit Breaker fail threshold",5 ,100 ,int (f .get ("cb_fail_threshold",30 )))
        f ["cb_cooldown_sec"]=st .slider ("Circuit Breaker cool down (sec)",10 ,600 ,int (f .get ("cb_cooldown_sec",60 )))
        merged ["filters"]=f 
        st .caption ("Note: worker_count/max_queue معمولاً نیاز به restart بات دارد تا کامل اعمال شود.")

    with tabs [3 ]:
        f =merged .get ("filters",{})
        f ["gold_ping_ms"]=st .slider ("Gold ping <= (ms)",50 ,500 ,int (f .get ("gold_ping_ms",150 )))
        f ["gold_need_ok"]=st .slider ("Gold need ok count",1 ,5 ,int (f .get ("gold_need_ok",3 )))
        merged ["filters"]=f 

    with tabs [4 ]:
        merged ["rename_text"]=st .text_input ("Rename Text (middle)",value =str (merged .get ("rename_text","MDMA")))
        merged ["post_interval_sec"]=st .number_input (
        "Post Interval (sec)",min_value =0 ,max_value =3600 ,value =int (merged .get ("post_interval_sec",10 ))
        )

    with tabs [5 ]:
        st .caption ("Changing sources/target usually needs bot restart to re-subscribe to chats.")
        src_text ="\n".join ([str (x )for x in (merged .get ("sources")or [])])
        new_src_text =st .text_area ("Sources (one per line)",value =src_text ,height =120 )
        merged ["sources"]=[s .strip ()for s in new_src_text .splitlines ()if s .strip ()]
        merged ["target_channel"]=st .text_input ("Target channel",value =str (merged .get ("target_channel","")))

    with tabs [6 ]:
        xray =merged .get ("xray",{})or {}
        curl =merged .get ("curl",{})or {}
        xray ["binary_path"]=st .text_input ("xray binary path",value =str (xray .get ("binary_path","./xray.exe")))
        curl ["binary_path"]=st .text_input ("curl binary path",value =str (curl .get ("binary_path","curl")))
        merged ["xray"]=xray 
        merged ["curl"]=curl 

    with tabs [7 ]:
        cap =merged .get ("caption",{})or {}
        cap ["fixed"]=st .text_area ("Fixed caption tail",value =str (cap .get ("fixed","\n\n—\n⚠️MDMA")),height =160 )
        merged ["caption"]=cap 

    with tabs [8 ]:
        st .json (merged ,expanded =False )

    col1 ,col2 =st .columns ([1 ,3 ])
    with col1 :
        if st .button ("Save Settings ✅"):
            db .set_settings_dict (merged )
            st .success ("Saved. Bot will pick safe switches live; other parts may need restart.")
    with col2 :
        st .caption ("Tip: برای امنیت بهتر روی سرور، پنل رو پشت Nginx + HTTPS + BasicAuth قرار بده.")


def page_events (db_path :str ):
    st .subheader ("Events Explorer")
    df =_cached_events (db_path ,limit =1000 )
    if df .empty :
        st .info ("No events yet.")
        return 

    kinds =["(all)"]+sorted ([x for x in df ["kind"].dropna ().unique ().tolist ()])
    statuses =["(all)"]+sorted ([x for x in df ["status"].dropna ().unique ().tolist ()])

    c1 ,c2 ,c3 =st .columns (3 )
    with c1 :
        ksel =st .selectbox ("Kind",kinds )
    with c2 :
        ssel =st .selectbox ("Status",statuses )
    with c3 :
        limit =st .slider ("Rows",50 ,1000 ,200 )

    dff =df .copy ()
    if ksel !="(all)":
        dff =dff [dff ["kind"]==ksel ]
    if ssel !="(all)":
        dff =dff [dff ["status"]==ssel ]

    if "time"not in dff .columns :
        dff ["time"]=dff ["ts"].apply (_ts_to_str )

    st .dataframe (
    dff .head (limit )[["time","kind","status","proto","source","msg_id","latency_ms","exit_ip","country_code","country","org","detail"]],
    use_container_width =True ,
    hide_index =True ,
    )


def main ():
    st .set_page_config (page_title ="MDMA Panel",layout ="wide")

    cfg =_load_cfg ()
    panel_cfg =cfg .get ("panel",{})or {}
    user =panel_cfg .get ("username","admin")
    pwd =panel_cfg .get ("password","admin")

    must_login (user ,pwd )

    db_path =cfg .get ("db_path","bot.db")
    db =DB (db_path )
    db .set_health ("panel","ok",{"ts":int (time .time ())})

    st .sidebar .title ("MDMA Panel")
    page =st .sidebar .radio ("Navigate",["Dashboard","Settings","Events"])

    window_hours =st .sidebar .slider ("Window (hours)",1 ,168 ,24 )
    st .sidebar .caption ("Refresh: use Rerun button if you want manual refresh.")
    if st .sidebar .button ("Rerun 🔄"):
        st .rerun ()

    if page =="Dashboard":
        page_dashboard (db ,db_path ,window_hours )
    elif page =="Settings":
        page_settings (cfg ,db )
    else :
        page_events (db_path )


if __name__ =="__main__":
    main ()

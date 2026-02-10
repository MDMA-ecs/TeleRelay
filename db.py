import json 
import sqlite3 
import time 
from typing import Any ,Dict ,List ,Optional 


class DB :
    def __init__ (self ,path :str ="bot.db"):
        self .path =path 
        self ._init ()

    def _conn (self )->sqlite3 .Connection :
        conn =sqlite3 .connect (self .path ,timeout =30 )
        conn .execute ("PRAGMA journal_mode=WAL;")
        conn .execute ("PRAGMA synchronous=NORMAL;")
        return conn 

    def _init (self )->None :
        with self ._conn ()as c :
            c .execute (
            """
                CREATE TABLE IF NOT EXISTS seen (
                    fp TEXT PRIMARY KEY,
                    first_seen_ts INTEGER,
                    last_seen_ts INTEGER
                )
                """
            )
            c .execute (
            """
                CREATE TABLE IF NOT EXISTS posted (
                    fp TEXT PRIMARY KEY,
                    posted_ts INTEGER
                )
                """
            )
            c .execute (
            """
                CREATE TABLE IF NOT EXISTS tests (
                    fp TEXT PRIMARY KEY,
                    status TEXT,
                    latency_ms INTEGER,
                    exit_ip TEXT,
                    country_code TEXT,
                    country TEXT,
                    asn TEXT,
                    org TEXT,
                    updated_ts INTEGER
                )
                """
            )
            c .execute (
            """
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_ts INTEGER
                )
                """
            )


            c .execute (
            """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts INTEGER,
                    kind TEXT,
                    source TEXT,
                    msg_id INTEGER,
                    fp TEXT,
                    proto TEXT,
                    status TEXT,
                    latency_ms INTEGER,
                    exit_ip TEXT,
                    country_code TEXT,
                    country TEXT,
                    asn TEXT,
                    org TEXT,
                    detail TEXT
                )
                """
            )
            c .execute ("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
            c .execute ("CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind)")
            c .execute ("CREATE INDEX IF NOT EXISTS idx_events_status ON events(status)")


            c .execute (
            """
                CREATE TABLE IF NOT EXISTS health (
                    component TEXT PRIMARY KEY,
                    status TEXT,
                    meta TEXT,
                    updated_ts INTEGER
                )
                """
            )


    def touch_seen (self ,fp :str )->None :
        ts =int (time .time ())
        with self ._conn ()as c :
            c .execute (
            """
                INSERT INTO seen(fp, first_seen_ts, last_seen_ts)
                VALUES(?,?,?)
                ON CONFLICT(fp) DO UPDATE SET last_seen_ts=excluded.last_seen_ts
                """,
            (fp ,ts ,ts ),
            )

    def mark_posted (self ,fp :str )->None :
        ts =int (time .time ())
        with self ._conn ()as c :
            c .execute (
            """
                INSERT INTO posted(fp, posted_ts)
                VALUES(?,?)
                ON CONFLICT(fp) DO UPDATE SET posted_ts=excluded.posted_ts
                """,
            (fp ,ts ),
            )

    def recently_posted (self ,fp :str ,window_hours :int )->bool :
        if window_hours <=0 :
            return False 
        limit_ts =int (time .time ())-int (window_hours )*3600 
        with self ._conn ()as c :
            row =c .execute ("SELECT posted_ts FROM posted WHERE fp=?",(fp ,)).fetchone ()
        if not row :
            return False 
        return int (row [0 ])>=limit_ts 


    def set_test_result (
    self ,
    fp :str ,
    status :str ,
    latency_ms :Optional [int ],
    exit_ip :Optional [str ],
    country_code :Optional [str ],
    country :Optional [str ],
    asn :Optional [str ],
    org :Optional [str ],
    )->None :
        ts =int (time .time ())
        with self ._conn ()as c :
            c .execute (
            """
                INSERT INTO tests(fp,status,latency_ms,exit_ip,country_code,country,asn,org,updated_ts)
                VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(fp) DO UPDATE SET
                    status=excluded.status,
                    latency_ms=excluded.latency_ms,
                    exit_ip=excluded.exit_ip,
                    country_code=excluded.country_code,
                    country=excluded.country,
                    asn=excluded.asn,
                    org=excluded.org,
                    updated_ts=excluded.updated_ts
                """,
            (fp ,status ,latency_ms ,exit_ip ,country_code ,country ,asn ,org ,ts ),
            )


    def set_settings_dict (self ,settings :Dict [str ,Any ])->None :
        ts =int (time .time ())
        payload =json .dumps (settings ,ensure_ascii =False )
        with self ._conn ()as c :
            c .execute (
            """
                INSERT INTO settings(key,value,updated_ts) VALUES(?,?,?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_ts=excluded.updated_ts
                """,
            ("runtime",payload ,ts ),
            )

    def get_settings_dict (self )->Optional [Dict [str ,Any ]]:
        with self ._conn ()as c :
            row =c .execute ("SELECT value FROM settings WHERE key=?",("runtime",)).fetchone ()
        if not row :
            return None 
        try :
            return json .loads (row [0 ])
        except Exception :
            return None 


    def add_event (
    self ,
    kind :str ,
    source :Optional [str ]=None ,
    msg_id :Optional [int ]=None ,
    fp :Optional [str ]=None ,
    proto :Optional [str ]=None ,
    status :Optional [str ]=None ,
    latency_ms :Optional [int ]=None ,
    exit_ip :Optional [str ]=None ,
    country_code :Optional [str ]=None ,
    country :Optional [str ]=None ,
    asn :Optional [str ]=None ,
    org :Optional [str ]=None ,
    detail :Optional [str ]=None ,
    )->None :
        ts =int (time .time ())
        with self ._conn ()as c :
            c .execute (
            """
                INSERT INTO events(ts,kind,source,msg_id,fp,proto,status,latency_ms,exit_ip,country_code,country,asn,org,detail)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
            (
            ts ,
            kind ,
            source ,
            msg_id ,
            fp ,
            proto ,
            status ,
            latency_ms ,
            exit_ip ,
            country_code ,
            country ,
            asn ,
            org ,
            detail ,
            ),
            )

    def get_events (
    self ,
    limit :int =200 ,
    since_ts :Optional [int ]=None ,
    kind :Optional [str ]=None ,
    status :Optional [str ]=None ,
    )->List [Dict [str ,Any ]]:
        q ="SELECT id,ts,kind,source,msg_id,fp,proto,status,latency_ms,exit_ip,country_code,country,asn,org,detail FROM events WHERE 1=1"
        params :List [Any ]=[]
        if since_ts is not None :
            q +=" AND ts >= ?"
            params .append (int (since_ts ))
        if kind :
            q +=" AND kind = ?"
            params .append (kind )
        if status :
            q +=" AND status = ?"
            params .append (status )
        q +=" ORDER BY ts DESC, id DESC LIMIT ?"
        params .append (int (limit ))

        with self ._conn ()as c :
            rows =c .execute (q ,tuple (params )).fetchall ()

        out :List [Dict [str ,Any ]]=[]
        for r in rows :
            out .append (
            {
            "id":r [0 ],
            "ts":r [1 ],
            "kind":r [2 ],
            "source":r [3 ],
            "msg_id":r [4 ],
            "fp":r [5 ],
            "proto":r [6 ],
            "status":r [7 ],
            "latency_ms":r [8 ],
            "exit_ip":r [9 ],
            "country_code":r [10 ],
            "country":r [11 ],
            "asn":r [12 ],
            "org":r [13 ],
            "detail":r [14 ],
            }
            )
        return out 


    def set_health (self ,component :str ,status :str ,meta :Optional [Dict [str ,Any ]]=None )->None :
        ts =int (time .time ())
        payload =json .dumps (meta or {},ensure_ascii =False )
        with self ._conn ()as c :
            c .execute (
            """
                INSERT INTO health(component,status,meta,updated_ts)
                VALUES(?,?,?,?)
                ON CONFLICT(component) DO UPDATE SET
                    status=excluded.status,
                    meta=excluded.meta,
                    updated_ts=excluded.updated_ts
                """,
            (component ,status ,payload ,ts ),
            )

    def get_health_all (self )->List [Dict [str ,Any ]]:
        with self ._conn ()as c :
            rows =c .execute ("SELECT component,status,meta,updated_ts FROM health ORDER BY component").fetchall ()
        out :List [Dict [str ,Any ]]=[]
        for r in rows :
            try :
                meta =json .loads (r [2 ])if r [2 ]else {}
            except Exception :
                meta ={}
            out .append ({"component":r [0 ],"status":r [1 ],"meta":meta ,"updated_ts":r [3 ]})
        return out 


    def get_kpis (self ,hours :int =24 )->Dict [str ,Any ]:
        since =int (time .time ())-int (hours )*3600 
        with self ._conn ()as c :
            posted =c .execute ("SELECT COUNT(*) FROM events WHERE ts>=? AND kind='posted'",(since ,)).fetchone ()[0 ]
            test_ok =c .execute ("SELECT COUNT(*) FROM events WHERE ts>=? AND kind='test' AND status='ok'",(since ,)).fetchone ()[0 ]
            test_fail =c .execute ("SELECT COUNT(*) FROM events WHERE ts>=? AND kind='test' AND status='fail'",(since ,)).fetchone ()[0 ]
            rx =c .execute ("SELECT COUNT(*) FROM events WHERE ts>=? AND kind='rx'",(since ,)).fetchone ()[0 ]
            avg_lat =c .execute (
            "SELECT AVG(latency_ms) FROM events WHERE ts>=? AND kind='test' AND status='ok' AND latency_ms IS NOT NULL",
            (since ,),
            ).fetchone ()[0 ]
        return {
        "hours":hours ,
        "rx":int (rx or 0 ),
        "posted":int (posted or 0 ),
        "test_ok":int (test_ok or 0 ),
        "test_fail":int (test_fail or 0 ),
        "avg_latency_ms":int (avg_lat )if avg_lat is not None else None ,
        }

    def get_timeseries (self ,hours :int =48 ,kind :str ="posted")->List [Dict [str ,Any ]]:
        since =int (time .time ())-int (hours )*3600 

        with self ._conn ()as c :
            rows =c .execute (
            """
                SELECT (ts/3600)*3600 AS bucket_ts, COUNT(*)
                FROM events
                WHERE ts>=? AND kind=?
                GROUP BY bucket_ts
                ORDER BY bucket_ts ASC
                """,
            (since ,kind ),
            ).fetchall ()
        return [{"ts":int (r [0 ]),"count":int (r [1 ])}for r in rows ]

    def get_top_countries (self ,hours :int =24 ,limit :int =10 )->List [Dict [str ,Any ]]:
        since =int (time .time ())-int (hours )*3600 
        with self ._conn ()as c :
            rows =c .execute (
            """
                SELECT COALESCE(country_code,'??') AS cc, COALESCE(country,'Unknown') AS country, COUNT(*)
                FROM events
                WHERE ts>=? AND kind='test' AND status='ok'
                GROUP BY cc, country
                ORDER BY COUNT(*) DESC
                LIMIT ?
                """,
            (since ,limit ),
            ).fetchall ()
        return [{"cc":r [0 ],"country":r [1 ],"count":int (r [2 ])}for r in rows ]

    def get_top_asn (self ,hours :int =24 ,limit :int =10 )->List [Dict [str ,Any ]]:
        since =int (time .time ())-int (hours )*3600 
        with self ._conn ()as c :
            rows =c .execute (
            """
                SELECT COALESCE(asn,'?') AS asn, COALESCE(org,'Unknown') AS org, COUNT(*)
                FROM events
                WHERE ts>=? AND kind='test' AND status='ok'
                GROUP BY asn, org
                ORDER BY COUNT(*) DESC
                LIMIT ?
                """,
            (since ,limit ),
            ).fetchall ()
        return [{"asn":r [0 ],"org":r [1 ],"count":int (r [2 ])}for r in rows ]

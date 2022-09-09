"""
grottconf  process command parameter and settings file
Updated: 2022-08-26
Version 2.7.6
"""

import argparse
import configparser as cp
import json
import os
from collections import defaultdict

from influxdb_client import InfluxDBClient
from influxdb_client.client.write_api import ASYNCHRONOUS as INFLUXDB_ASYNCHRONOUS

from grottdata import pr, str2bool

_UNSET = object()


def get_option_environ(option):
    return os.getenv(f"g{option}")


class CustomConfigParser(cp.ConfigParser):
    def __init__(self, *args, **kwargs):
        self.section_opt_pairing = defaultdict(list)
        return super().__init__(*args, **kwargs)

    def has_option(self, section: str, option: str, environ_key=_UNSET) -> bool:
        if get_option_environ(option if environ_key is _UNSET else environ_key):
            return True
        return super().has_option(section, option)

    def has_option_store_confname(
        self, section, option, confvar=_UNSET, **kwargs
    ) -> bool:
        if confvar is _UNSET:
            confvar = option
        self.section_opt_pairing[section].append((option, confvar))
        return self.has_option(section, option, **kwargs)

    def _get_conv(self, *args, **kwargs):
        _, option, conv = args
        environ_key = _UNSET
        if "environ_key" in kwargs:
            environ_key = kwargs["environ_key"]
            del kwargs["environ_key"]
        if environ_value := get_option_environ(
            option if environ_key is _UNSET else environ_key
        ):
            return conv(environ_value)
        return super()._get_conv(*args, **kwargs)

    def get(self, *args, **kwargs):
        _, option = args
        environ_key = _UNSET
        if "environ_key" in kwargs:
            environ_key = kwargs["environ_key"]
            del kwargs["environ_key"]

        if environ_value := get_option_environ(
            option if environ_key is _UNSET else environ_key
        ):
            return environ_value
        return super().get(*args, **kwargs)


class Conf:
    def __init__(self, vrm):
        self.config = None
        self.verrel = vrm

        # Set default variables
        self.verbose = False
        self.trace = False
        self.cfgfile = "grott.ini"
        self.minrecl = 100
        self.invtype = "default"  # specify sepcial invertype default (spf, sph)
        self.invtypemap = {}
        self.includeall = False  # Include all defined keys from layout (also incl = no)
        self.noipf = False  # Allow IP change if needed
        self.gtime = "auto"  # time used =  auto: use record time or if not valid server time, alternative server: use always server time
        self.sendbuf = True  # enable / disable sending historical data from buffer
        self.inverterid = "automatic"
        self.mode = "proxy"
        self.grottport = 5279
        self.grottip = "default"  # connect to server IP adress
        self.tmzone = "local"  # set timezone (at this moment only used for influxdb)
        self.timeout = 300.0  # timeout for socket to datalogger (and forwarding socket when in proxy mode only)

        # Grott server mode
        self.httphost = "0.0.0.0"
        self.httpport = 5782
        self.httptoken = None
        self.registerreadtimeout = 7.0
        self.registerwritetimeout = 15.0
        self.firstping = False
        self.sendseq = 1
        self.serverforward = False
        self.httptimeout = 10.0
        self.forwardretry = 1
        self.forwardtimeout = 2.0
        self.write_delay_ms = 100

        # Growatt server default
        self.growattip = "47.91.67.66"
        self.growattport = 5279

        # MQTT default
        self.mqttip = "localhost"
        self.mqttport = 1883
        self.mqtttopic = "energy/growatt"
        self.mqttmtopic = "False"
        self.mqttdeviceidintopic = False
        self.mqttmtopicname = "energy/meter"
        self.nomqtt = False  # not in ini file, can only be changed via start parms
        self.mqttauth = False
        self.mqttuser = "grott"
        self.mqttpsw = "growatt2020"
        self.mqttretain = False

        # pvoutput default
        self.pvoutput = False
        self.pvinverters = 1
        self.pvurl = "https://pvoutput.org/service/r2/addstatus.jsp"
        self.pvapikey = "yourapikey"
        self.pvsystemid = {}
        self.pvinverterid = {}
        self.pvsystemid[1] = "systemid1"
        self.pvinverterid[1] = "inverter1"
        self.pvdisv1 = False
        self.pvtemp = False
        self.pvtimeout = 2.5

        # influxdb default
        self.influx = False
        self.ifurl = "http://localhost:8086"
        self.iftoken = "influx_token"
        self.iforg = "grottorg"
        self.ifbucket = "grottdb"

        # extension
        self.extension = False
        self.extname = "grottext"
        # self.extvar = {"ip": "localhost", "port":8000}
        self.extvar = {"none": "none"}

        pr("Grott Growatt logging monitor : " + self.verrel)

        # Set parm's
        # prio: 1.Command line parms, 2.env. variables, 3.config file 4.program default
        # process command settings that set processing values (verbose, trace, output, config, nomqtt)
        self.parserinit()

        # Process config file and environmental variable
        self.procconf()

        # Process command line arguments
        self.parserset()

        # prepare MQTT security
        if not self.mqttauth:
            self.pubauth = None
        else:
            self.pubauth = dict(username=self.mqttuser, password=self.mqttpsw)

        # define recordlayouts
        self.set_reclayouts()

        # prepare influxDB
        if self.influx:
            if self.verbose:
                pr("\n- Grott InfluxDB initiating started")

            self.influxclient = InfluxDBClient(
                url=self.ifurl,
                org=self.iforg,
                token=self.iftoken,
            )
            self.ifbucket_api = self.influxclient.buckets_api()
            self.iforganization_api = self.influxclient.organizations_api()
            self.ifwrite_api = self.influxclient.write_api(
                write_options=INFLUXDB_ASYNCHRONOUS
            )

    def print(self):
        pr("\nGrott settings:\n")

        for section, variables in self.config.section_opt_pairing.items():
            pr(f"_{section}:")
            for option, confname in variables:
                try:
                    value = eval(f"self.{confname}")
                except AttributeError:
                    try:
                        int(confname[-1])
                        head = confname.rstrip("0123456789")
                        if not (
                            isinstance(eval(f"self.{head}"), list)
                            or isinstance(eval(f"self.{head}"), dict)
                        ):
                            raise Exception
                        tail = confname[len(head) :]
                        value = eval(f"self.{head}[{tail}]")
                    except Exception:
                        value = "N/A"

                if option in ("httptoken", "password", "apikey", "token"):
                    value = "**secret**"

                pr("\t%-30s\t%s" % (option, value))

        pr()

    def parserinit(self):
        """
        Process commandline parameters init (read args, process c,v,o settings)
        """
        parser = argparse.ArgumentParser(prog="grott")
        parser.add_argument("-v", "--verbose", help="set verbose", action="store_true")
        parser.add_argument("--version", action="version", version=self.verrel)
        parser.add_argument(
            "-c",
            help="set config file if not specified config file is grott.ini",
            metavar="[config file]",
        )
        parser.add_argument(
            "-m",
            help="set mode (sniff or proxy or server)",
            metavar="[mode]",
        )
        parser.add_argument(
            "-i",
            help="set inverterid, if not specified inverterid of .ini file is used",
            metavar="[inverterid]",
        )
        parser.add_argument(
            "-nm", "--nomqtt", help="disable mqtt send", action="store_true"
        )
        parser.add_argument(
            "-t",
            "--trace",
            help="enable trace, use in addition to verbose option (only available in sniff mode)",
            action="store_true",
        )
        parser.add_argument(
            "-p",
            "--pvoutput",
            help="enable pvoutput send (True/False)",
            action="store_true",
        )
        parser.add_argument(
            "-n",
            "--noipf",
            help="Allow IP change from growatt website",
            action="store_true",
        )

        args, unknown = parser.parse_known_args()

        if args.c is not None:
            self.cfgfile = args.c
        self.verbose = args.verbose
        self.anomqtt = args.nomqtt
        self.apvoutput = args.pvoutput
        self.trace = args.trace
        self.anoipf = args.noipf

        if args.m is not None:
            self.amode = args.m

        if args.i is not None and args.i != "none":  # added none for docker support
            self.ainverterid = args.i

        if self.verbose:
            pr("\nGrott Command line parameters processed:")
            pr("\tverbose:              \t", self.verbose)
            pr("\tconfig file:          \t", self.cfgfile)
            pr("\tnomqtt:               \t", self.anomqtt)
            pr("\tinverterid:           \t", self.inverterid)
            pr("\tpvoutput:             \t", self.apvoutput)
            pr("\tnoipf:                \t", self.noipf)

    def parserset(self):
        pr("\nGrott override settings if set in commandline")
        if hasattr(self, "amode"):
            self.mode = self.amode
        if hasattr(self, "anoipf") and self.anoipf:
            self.noipf = self.anoipf
        if hasattr(self, "ainverterid"):
            self.inverterid = self.ainverterid
        if hasattr(self, "anomqtt") and self.anomqtt:
            self.nomqtt = self.anomqtt
        if hasattr(self, "apvoutput") and self.apvoutput:
            self.pvoutput = self.apvoutput

    def procconf(self):
        pr("\nGrott process configuration file")
        config = CustomConfigParser()
        self.config = config
        config.read(self.cfgfile)
        if config.has_option_store_confname("Generic", "minrecl"):
            self.minrecl = config.getint("Generic", "minrecl")
        if config.has_option_store_confname("Generic", "verbose"):
            self.verbose = config.getboolean("Generic", "verbose")
        if config.has_option_store_confname("Generic", "includeall"):
            self.includeall = config.getboolean("Generic", "includeall")
        if config.has_option_store_confname("Generic", "invtype"):
            self.invtype = config.get("Generic", "invtype")
        if config.has_option_store_confname("Generic", "invtypemap"):
            self.invtypemap = eval(config.get("Generic", "invtypemap"))
        if config.has_option_store_confname("Generic", "inverterid"):
            self.inverterid = config.get("Generic", "inverterid")
        if config.has_option_store_confname("Generic", "noipf"):
            self.noipf = config.getboolean("Generic", "noipf")
        if config.has_option_store_confname("Generic", "time", "gtime"):
            self.gtime = config.get("Generic", "time")
        if config.has_option_store_confname("Generic", "sendbuf"):
            self.sendbuf = config.getboolean("Generic", "sendbuf")
        if config.has_option_store_confname("Generic", "timezone", "tmzone"):
            self.tmzone = config.get("Generic", "timezone")
        if config.has_option_store_confname("Generic", "mode"):
            self.mode = config.get("Generic", "mode")
        if config.has_option_store_confname(
            "Generic", "ip", "grottip", environ_key="grottip"
        ):
            self.grottip = config.get("Generic", "ip", environ_key="grottip")
        if config.has_option_store_confname(
            "Generic", "port", "grottport", environ_key="grottport"
        ):
            self.grottport = config.getint("Generic", "port", environ_key="grottport")
        if config.has_option_store_confname("Generic", "timeout"):
            self.timeout = config.getfloat("Generic", "timeout")

        if config.has_option_store_confname(
            "Growatt", "ip", "growattip", environ_key="growattip"
        ):
            self.growattip = config.get("Growatt", "ip", environ_key="growattip")
        if config.has_option_store_confname(
            "Growatt", "port", "growattport", environ_key="growattport"
        ):
            self.growattport = config.getint(
                "Growatt", "port", environ_key="growattport"
            )
        if config.has_option_store_confname("Server", "httpip", "httphost"):
            self.httphost = config.get("Server", "httpip")
        if config.has_option_store_confname("Server", "httpport"):
            self.httpport = config.getint("Server", "httpport")
        if config.has_option_store_confname("Server", "httptoken"):
            self.httptoken = config.get("Server", "httptoken")

        if config.has_option_store_confname("Server", "httptimeout"):
            self.httptimeout = config.getfloat("Server", "httptimeout")
        if config.has_option_store_confname("Server", "registerreadtimeout"):
            self.registerreadtimeout = config.getfloat("Server", "registerreadtimeout")
        if config.has_option_store_confname("Server", "registerwritetimeout"):
            self.registerwritetimeout = config.getfloat("HTTP", "registerwritetimeout")
        if config.has_option_store_confname("Server", "firstping"):
            self.firstping = config.getboolean("Server", "firstping")
        if config.has_option_store_confname("Server", "sendseq"):
            self.sendseq = config.getint("Server", "sendseq")
        if config.has_option_store_confname("Server", "serverforward"):
            self.serverforward = config.getboolean("Server", "serverforward")
        if config.has_option_store_confname("Server", "forwardretry"):
            self.forwardretry = config.getint("Server", "forwardretry")
        if config.has_option_store_confname("Server", "forwardtimeout"):
            self.forwardtimeout = config.getfloat("Server", "forwardtimeout")
        if config.has_option_store_confname("Server", "write_delay_ms"):
            self.write_delay_ms = config.getfloat("Server", "write_delay_ms")

        if config.has_option_store_confname("MQTT", "nomqtt"):
            self.nomqtt = config.getboolean("MQTT", "nomqtt")
        if config.has_option_store_confname(
            "MQTT", "ip", "mqttip", environ_key="mqttip"
        ):
            self.mqttip = config.get("MQTT", "ip", environ_key="mqttip")
        if config.has_option_store_confname(
            "MQTT", "port", "mqttport", environ_key="mqttport"
        ):
            self.mqttport = config.getint("MQTT", "port", environ_key="mqttport")
        if config.has_option_store_confname(
            "MQTT", "topic", "mqtttopic", environ_key="mqtttopic"
        ):
            self.mqtttopic = config.get("MQTT", "topic", environ_key="mqtttopic")
        if config.has_option_store_confname(
            "MQTT",
            "deviceidintopic",
            "mqttdeviceidintopic",
            environ_key="mqttdeviceidintopic",
        ):
            self.mqttdeviceidintopic = config.getboolean(
                "MQTT", "deviceidintopic", environ_key="mqttdeviceidintopic"
            )
        if config.has_option_store_confname(
            "MQTT", "mtopic", "mqttmtopic", environ_key="mqttmtopic"
        ):
            self.mqttmtopic = config.getboolean(
                "MQTT", "mtopic", environ_key="mqttmtopic"
            )
        if config.has_option_store_confname(
            "MQTT", "mtopicname", "mqttmtopicname", environ_key="mqttmtopicname"
        ):
            self.mqttmtopicname = config.get(
                "MQTT", "mtopicname", environ_key="mqttmtopicname"
            )
        if config.has_option_store_confname(
            "MQTT", "retain", "mqttretain", environ_key="mqttretain"
        ):
            self.mqttretain = config.getboolean(
                "MQTT", "retain", environ_key="mqttretain"
            )
        if config.has_option_store_confname(
            "MQTT", "auth", "mqttauth", environ_key="mqttauth"
        ):
            self.mqttauth = config.getboolean("MQTT", "auth", environ_key="mqttauth")
        if config.has_option_store_confname(
            "MQTT", "user", "mqttuser", environ_key="mqttuser"
        ):
            self.mqttuser = config.get("MQTT", "user", environ_key="mqttuser")
        if config.has_option_store_confname(
            "MQTT", "password", "mqttpsw", environ_key="mqttpassword"
        ):
            self.mqttpsw = config.get("MQTT", "password", environ_key="mqttpassword")

        if config.has_option_store_confname("PVOutput", "pvoutput"):
            self.pvoutput = config.getboolean("PVOutput", "pvoutput")
        if config.has_option_store_confname("PVOutput", "pvtemp"):
            self.pvtemp = config.getboolean("PVOutput", "pvtemp")
        if config.has_option_store_confname("PVOutput", "pvdisv1"):
            self.pvdisv1 = config.getboolean("PVOutput", "pvdisv1")
        if config.has_option_store_confname("PVOutput", "pvinverters"):
            self.pvinverters = config.getint("PVOutput", "pvinverters")
        if config.has_option_store_confname("PVOutput", "apikey", "pvapikey"):
            self.pvapikey = config.get("PVOutput", "apikey", environ_key="pvapikey")
        # if more inverter are installed at the same interface (shinelink) get systemids
        # if self.pvinverters > 1 :
        for x in range(self.pvinverters + 1):
            if x == 0:
                continue

            if config.has_option_store_confname(
                "PVOutput", f"systemid{x}", f"pvsystemid{x}"
            ):
                self.pvsystemid[x] = config.get("PVOutput", f"systemid{x}")
            if config.has_option_store_confname(
                "PVOutput", f"inverterid{x}", f"pvinverterid{x}"
            ):
                self.pvinverterid[x] = config.get("PVOutput", f"inverterid{x}")
        if self.pvinverters == 1:
            if config.has_option_store_confname("PVOutput", "systemid", "pvsystemid1"):
                self.pvsystemid[1] = config.get("PVOutput", "systemid")
        if config.has_option_store_confname("PVOutput", "pvtimeout"):
            self.pvtimeout = config.getfloat("PVOutput", "pvtimeout")

        # INFLUX
        if config.has_option_store_confname("influx", "influx"):
            self.influx = config.getboolean("influx", "influx")
        if config.has_option_store_confname(
            "influx", "url", "ifurl", environ_key="ifurl"
        ):
            self.ifurl = config.get("influx", "url", environ_key="ifurl")
        if config.has_option_store_confname(
            "influx", "org", "iforg", environ_key="iforg"
        ):
            self.iforg = config.get("influx", "org", environ_key="iforg")
        if config.has_option_store_confname(
            "influx", "bucket", "ifbucket", environ_key="ifbucket"
        ):
            self.ifbucket = config.get("influx", "bucket", environ_key="ifbucket")
        if config.has_option_store_confname(
            "influx", "token", "iftoken", environ_key="iftoken"
        ):
            self.iftoken = config.get("influx", "token", environ_key="iftoken")

        # extension
        if config.has_option_store_confname("extension", "extension"):
            self.extension = config.getboolean("extension", "extension")
        if config.has_option_store_confname("extension", "extname"):
            self.extname = config.get("extension", "extname")
        if config.has_option_store_confname("extension", "extvar"):
            self.extvar = eval(config.get("extension", "extvar"))

    def set_reclayouts(self):
        # define record layout to be used based on byte 4,6,7 of the header T+byte4+byte6+byte7
        self.recorddict = {}

        # fmt: off
        self.recorddict1 = {
            "T02NNNN": {
                "decrypt": {"value": "False"},
                "datalogserial": {"value": 16,"length": 10,"type": "text","incl": "yes",},
                "pvserial": {"value": 36, "length": 10, "type": "text"},
                "date": {"value": 56, "divide": 10},
                "recortype1": {"value": 70, "length": 2, "type": "num", "incl": "no"},
                "recortype2": {"value": 74, "length": 2, "type": "num", "incl": "no"},
                "pvstatus": {"value": 78, "length": 2, "type": "num"},
                "pvpowerin": {"value": 82, "length": 4, "type": "num", "divide": 10},
                "pv1voltage": {"value": 90, "length": 2, "type": "num", "divide": 10},
                "pv1current": {"value": 94, "length": 2, "type": "num", "divide": 10},
                "pv1watt": {"value": 98, "length": 4, "type": "num", "divide": 10},
                "pv2voltage": {"value": 106, "length": 2, "type": "num", "divide": 10},
                "pv2current": {"value": 110, "length": 2, "type": "num", "divide": 10},
                "pv2watt": {"value": 114, "length": 4, "type": "num", "divide": 10},
                "pvpowerout": {"value": 122, "length": 4, "type": "num", "divide": 10},
                "pvfrequentie": {"value": 130,"length": 2,"type": "num","divide": 100,},
                "pvgridvoltage": {"value": 134,"length": 2,"type": "num","divide": 10,},
                "pvgridcurrent": {"value": 138,"length": 2,"type": "num","divide": 10,},
                "pvgridpower": {"value": 142, "length": 4, "type": "num", "divide": 10},
                "pvgridvoltage2": {"value": 150,"length": 2,"type": "num","divide": 10,},
                "pvgridcurrent2": {"value": 154,"length": 2,"type": "num","divide": 10,},
                "pvgridpower2": {"value": 158,"length": 4,"type": "num","divide": 10,},
                "pvgridvoltage3": {"value": 166,"length": 2,"type": "num","divide": 10,},
                "pvgridcurrent3": {"value": 170,"length": 2,"type": "num","divide": 10,},
                "pvgridpower3": {"value": 174,"length": 4,"type": "num","divide": 10,},
                "pvenergytoday": {"value": 182,"length": 4,"type": "num","divide": 10,},
                "pvenergytotal": {"value": 190,"length": 4,"type": "num","divide": 10,},
                "totworktime": {"value": 198,"length": 4,"type": "num","divide": 7200,},
                "pvtemperature": {"value": 206,"length": 2,"type": "num","divide": 10,},
                "isof": {"value": 210,"length": 2,"type": "num","divide": 1,"incl": "no",},
                "gfcif": {"value": 214,"length": 2,"type": "num","divide": 1,"incl": "no",},
                "dcif": {"value": 218,"length": 2,"type": "num","divide": 1,"incl": "no",},
                "vpvfault": {"value": 222,"length": 2,"type": "num","divide": 1,"incl": "no",},
                "vacfault": {"value": 226,"length": 2,"type": "num","divide": 1,"incl": "no",},
                "facfault": {"value": 230,"length": 2,"type": "num","divide": 1,"incl": "no",},
                "tmpfault": {"value": 234,"length": 2,"type": "num","divide": 1,"incl": "no",},
                "faultcode": {"value": 238,"length": 2,"type": "num","divide": 1,"incl": "no",},
                "pvipmtemperature": {"value": 242,"length": 2,"type": "num","divide": 10,},
                "pbusvolt": {"value": 246,"length": 2,"type": "num","divide": 10,"incl": "no",},
                "nbusvolt": {"value": 250,"length": 2,"type": "num","divide": 10,"incl": "no",},
                "epv1today": {"value": 278, "length": 4, "type": "num", "divide": 10},
                "epv1total": {"value": 286, "length": 4, "type": "num", "divide": 10},
                "epv2today": {"value": 294, "length": 4, "type": "num", "divide": 10},
                "epv2total": {"value": 302, "length": 4, "type": "num", "divide": 10},
                "epvtotal": {"value": 310, "length": 4, "type": "num", "divide": 10},
                "rac": {"value": 318,"length": 4,"type": "num","divide": 1,"incl": "no",},
                "eractoday": {"value": 326,"length": 4,"type": "num","divide": 1,"incl": "no",},
                "eractotal": {"value": 334,"length": 4,"type": "num","divide": 1,"incl": "no",},
            }
        }

        self.recorddict2 = {
            "T05NNNN": {
                "decrypt": {"value": "True"},
                "datalogserial": {"value": 16,"length": 10,"type": "text","incl": "yes",},
                "pvserial": {"value": 36, "length": 10, "type": "text"},
                "date": {"value": 56, "divide": 10},
                "recortype1": {"value": 70, "length": 2, "type": "num", "incl": "no"},
                "recortype2": {"value": 74, "length": 2, "type": "num", "incl": "no"},
                "pvstatus": {"value": 78, "length": 2, "type": "num"},
                "pvpowerin": {"value": 82, "length": 4, "type": "num", "divide": 10},
                "pv1voltage": {"value": 90, "length": 2, "type": "num", "divide": 10},
                "pv1current": {"value": 94, "length": 2, "type": "num", "divide": 10},
                "pv1watt": {"value": 98, "length": 4, "type": "num", "divide": 10},
                "pv2voltage": {"value": 106, "length": 2, "type": "num", "divide": 10},
                "pv2current": {"value": 110, "length": 2, "type": "num", "divide": 10},
                "pv2watt": {"value": 114, "length": 4, "type": "num", "divide": 10},
                "pvpowerout": {"value": 122, "length": 4, "type": "numx", "divide": 10},
                "pvfrequentie": {"value": 130,"length": 2,"type": "num","divide": 100,},
                "pvgridvoltage": {"value": 134,"length": 2,"type": "num","divide": 10,},
                "pvgridcurrent": {"value": 138,"length": 2,"type": "num","divide": 10,},
                "pvgridpower": {"value": 142, "length": 4, "type": "num", "divide": 10},
                "pvgridvoltage2": {"value": 150,"length": 2,"type": "num","divide": 10,},
                "pvgridcurrent2": {"value": 154,"length": 2,"type": "num","divide": 10,},
                "pvgridpower2": {"value": 158,"length": 4,"type": "num","divide": 10,},
                "pvgridvoltage3": {"value": 166,"length": 2,"type": "num","divide": 10,},
                "pvgridcurrent3": {"value": 170,"length": 2,"type": "num","divide": 10,},
                "pvgridpower3": {"value": 174,"length": 4,"type": "num","divide": 10,},
                "pvenergytoday": {"value": 182,"length": 4,"type": "num","divide": 10,},
                "pvenergytotal": {"value": 190,"length": 4,"type": "num","divide": 10,},
                "totworktime": {"value": 198,"length": 4,"type": "num","divide": 7200,},
                "pvtemperature": {"value": 206,"length": 2,"type": "num","divide": 10,},
                "isof": {"value": 210,"length": 2,"type": "num","divide": 1,"incl": "no",},
                "gfcif": {"value": 214,"length": 2,"type": "num","divide": 1,"incl": "no",},
                "dcif": {"value": 218,"length": 2,"type": "num","divide": 1,"incl": "no",},
                "vpvfault": {"value": 222,"length": 2,"type": "num","divide": 1,"incl": "no",},
                "vacfault": {"value": 226,"length": 2,"type": "num","divide": 1,"incl": "no",},
                "facfault": {"value": 230,"length": 2,"type": "num","divide": 1,"incl": "no",},
                "tmpfault": {"value": 234,"length": 2,"type": "num","divide": 1,"incl": "no",},
                "faultcode": {"value": 238,"length": 2,"type": "num","divide": 1,"incl": "no",},
                "pvipmtemperature": {"value": 242,"length": 2,"type": "num","divide": 10,},
                "pbusvolt": {"value": 246,"length": 2,"type": "num","divide": 10,"incl": "no",},
                "nbusvolt": {"value": 250,"length": 2,"type": "num","divide": 10,"incl": "no",},
                "epv1today": {"value": 278, "length": 4, "type": "num", "divide": 10},
                "epv1total": {"value": 286, "length": 4, "type": "num", "divide": 10},
                "epv2today": {"value": 294, "length": 4, "type": "num", "divide": 10},
                "epv2total": {"value": 302, "length": 4, "type": "num", "divide": 10},
                "epvtotal": {"value": 310, "length": 4, "type": "num", "divide": 10},
                "rac": {"value": 318,"length": 4,"type": "num","divide": 1,"incl": "no",},
                "eractoday": {"value": 326,"length": 4,"type": "num","divide": 1,"incl": "no",},
                "eractotal": {"value": 334,"length": 4,"type": "num","divide": 1,"incl": "no",},
            }
        }

        self.recorddict4 = {
            "T05NNNNX": {
                "decrypt": {"value": "True"},
                "datalogserial": {"value": 16,"length": 10,"type": "text","incl": "yes",},
                "pvserial": {"value": 36, "length": 10, "type": "text"},
                "date": {"value": 56, "divide": 10},
                "recortype1": {"value": 70, "length": 2, "type": "num", "incl": "no"},
                "recortype2": {"value": 74, "length": 2, "type": "num", "incl": "no"},
                "pvstatus": {"value": 78, "length": 2, "type": "num"},
                "pvpowerin": {"value": 82, "length": 4, "type": "num", "divide": 10},
                "pv1voltage": {"value": 90, "length": 2, "type": "num", "divide": 10},
                "pv1current": {"value": 94, "length": 2, "type": "num", "divide": 10},
                "pv1watt": {"value": 98, "length": 4, "type": "num", "divide": 10},
                "pv2voltage": {"value": 106, "length": 2, "type": "num", "divide": 10},
                "pv2current": {"value": 110, "length": 2, "type": "num", "divide": 10},
                "pv2watt": {"value": 114, "length": 4, "type": "num", "divide": 10},
                "pvpowerout": {"value": 170, "length": 4, "type": "numx", "divide": 10},
                "pvfrequentie": {"value": 178,"length": 2,"type": "num","divide": 100,},
                "pvgridvoltage": {"value": 182,"length": 2,"type": "num","divide": 10,},
                "pvgridcurrent": {"value": 186,"length": 2,"type": "num","divide": 10,},
                "pvgridpower": {"value": 190, "length": 4, "type": "num", "divide": 10},
                "pvgridvoltage2": {"value": 198,"length": 2,"type": "num","divide": 10,},
                "pvgridcurrent2": {"value": 202,"length": 2,"type": "num","divide": 10,},
                "pvgridpower2": {"value": 206,"length": 4,"type": "num","divide": 10,},
                "pvgridvoltage3": {"value": 214,"length": 2,"type": "num","divide": 10,},
                "pvgridcurrent3": {"value": 218,"length": 2,"type": "num","divide": 10,},
                "pvgridpower3": {"value": 222,"length": 4,"type": "num","divide": 10,},
                "totworktime": {"value": 266,"length": 4,"type": "num","divide": 7200,},
                "pvenergytoday": {"value": 274,"length": 4,"type": "num","divide": 10,},
                "pvenergytotal": {"value": 282,"length": 4,"type": "num","divide": 10,},
                "epvtotal": {"value": 290, "length": 4, "type": "num", "divide": 10},
                "epv1today": {"value": 298, "length": 4, "type": "num", "divide": 10},
                "epv1total": {"value": 306, "length": 4, "type": "num", "divide": 10},
                "epv2today": {"value": 314, "length": 4, "type": "num", "divide": 10},
                "epv2total": {"value": 322, "length": 4, "type": "num", "divide": 10},
                "pvtemperature": {"value": 450,"length": 2,"type": "num","divide": 10,},
                "pvipmtemperature": {"value": 466,"length": 2,"type": "num","divide": 10,},
                "pbusvolt": {"value": 470,"length": 2,"type": "num","divide": 10,"incl": "no",},
                "nbusvolt": {"value": 474,"length": 2,"type": "num","divide": 10,"incl": "no",},
            }
        }

        self.recorddict3 = {
            "T06NNNN": {
                "decrypt": {"value": "True"},
                "datalogserial": {"value": 16,"length": 10,"type": "text","incl": "yes",},
                "pvserial": {"value": 76, "length": 10, "type": "text"},
                "date": {"value": 136, "divide": 10},
                "recortype1": {"value": 150, "length": 2, "type": "num", "incl": "no"},
                "recortype2": {"value": 154, "length": 2, "type": "num", "incl": "no"},
                "pvstatus": {"value": 158, "length": 2, "type": "num"},
                "pvpowerin": {"value": 162, "length": 4, "type": "num", "divide": 10},
                "pv1voltage": {"value": 170, "length": 2, "type": "num", "divide": 10},
                "pv1current": {"value": 174, "length": 2, "type": "num", "divide": 10},
                "pv1watt": {"value": 178, "length": 4, "type": "num", "divide": 10},
                "pv2voltage": {"value": 186, "length": 2, "type": "num", "divide": 10},
                "pv2current": {"value": 190, "length": 2, "type": "num", "divide": 10},
                "pv2watt": {"value": 194, "length": 4, "type": "num", "divide": 10},
                "pvpowerout": {"value": 202, "length": 4, "type": "numx", "divide": 10},
                "pvfrequentie": {"value": 210,"length": 2,"type": "num","divide": 100,},
                "pvgridvoltage": {"value": 214,"length": 2,"type": "num","divide": 10,},
                "pvgridcurrent": {"value": 218,"length": 2,"type": "num","divide": 10,},
                "pvgridpower": {"value": 222, "length": 4, "type": "num", "divide": 10},
                "pvgridvoltage2": {"value": 230,"length": 2,"type": "num","divide": 10,},
                "pvgridcurrent2": {"value": 234,"length": 2,"type": "num","divide": 10,},
                "pvgridpower2": {"value": 238,"length": 4,"type": "num","divide": 10,},
                "pvgridvoltage3": {"value": 246,"length": 2,"type": "num","divide": 10,},
                "pvgridcurrent3": {"value": 250,"length": 2,"type": "num","divide": 10,},
                "pvgridpower3": {"value": 254,"length": 4,"type": "num","divide": 10,},
                "pvenergytoday": {"value": 262,"length": 4,"type": "num","divide": 10,},
                "pvenergytotal": {"value": 270,"length": 4,"type": "num","divide": 10,},
                "totworktime": {"value": 278,"length": 4,"type": "num","divide": 7200,},
                "pvtemperature": {"value": 286,"length": 2,"type": "num","divide": 10,},
                "isof": {"value": 290,"length": 2,"type": "num","divide": 1,"incl": "no",},
                "gfcif": {"value": 294,"length": 2,"type": "num","divide": 1,"incl": "no",},
                "dcif": {"value": 298,"length": 2,"type": "num","divide": 1,"incl": "no",},
                "vpvfault": {"value": 302,"length": 2,"type": "num","divide": 1,"incl": "no",},
                "vacfault": {"value": 306,"length": 2,"type": "num","divide": 1,"incl": "no",},
                "facfault": {"value": 310,"length": 2,"type": "num","divide": 1,"incl": "no",},
                "tmpfault": {"value": 314,"length": 2,"type": "num","divide": 1,"incl": "no",},
                "faultcode": {"value": 318,"length": 2,"type": "num","divide": 1,"incl": "no",},
                "pvipmtemperature": {"value": 322,"length": 2,"type": "num","divide": 10,},
                "pbusvolt": {"value": 326,"length": 2,"type": "num","divide": 10,"incl": "no",},
                "nbusvolt": {"value": 330,"length": 2,"type": "num","divide": 10,"incl": "no",},
                "epv1today": {"value": 358, "length": 4, "type": "num", "divide": 10},
                "epv1total": {"value": 366, "length": 4, "type": "num", "divide": 10},
                "epv2today": {"value": 374, "length": 4, "type": "num", "divide": 10},
                "epv2total": {"value": 382, "length": 4, "type": "num", "divide": 10},
                "epvtotal": {"value": 390, "length": 4, "type": "num", "divide": 10},
            }
        }

        self.recorddict5 = {
            "T06NNNNX": {
                "decrypt": {"value": "True"},
                "datalogserial": {"value": 16,"length": 10,"type": "text","incl": "yes",},
                "pvserial": {"value": 76, "length": 10, "type": "text"},
                "date": {"value": 136, "divide": 10},
                "recortype1": {"value": 150, "length": 2, "type": "num", "incl": "no"},
                "recortype2": {"value": 154, "length": 2, "type": "num", "incl": "no"},
                "pvstatus": {"value": 158, "length": 2, "type": "num"},
                "pvpowerin": {"value": 162, "length": 4, "type": "num", "divide": 10},
                "pv1voltage": {"value": 170, "length": 2, "type": "num", "divide": 10},
                "pv1current": {"value": 174, "length": 2, "type": "num", "divide": 10},
                "pv1watt": {"value": 178, "length": 4, "type": "num", "divide": 10},
                "pv2voltage": {"value": 186, "length": 2, "type": "num", "divide": 10},
                "pv2current": {"value": 190, "length": 2, "type": "num", "divide": 10},
                "pv2watt": {"value": 194, "length": 4, "type": "num", "divide": 10},
                "pvpowerout": {"value": 250, "length": 4, "type": "numx", "divide": 10},
                "pvfrequentie": {"value": 258,"length": 2,"type": "num","divide": 100,},
                "pvgridvoltage": {"value": 262,"length": 2,"type": "num","divide": 10,},
                "pvgridcurrent": {"value": 266,"length": 2,"type": "num","divide": 10,},
                "pvgridpower": {"value": 270, "length": 4, "type": "num", "divide": 10},
                "pvgridvoltage2": {"value": 278,"length": 2,"type": "num","divide": 10,},
                "pvgridcurrent2": {"value": 282,"length": 2,"type": "num","divide": 10,},
                "pvgridpower2": {"value": 286,"length": 4,"type": "num","divide": 10,},
                "pvgridvoltage3": {"value": 294,"length": 2,"type": "num","divide": 10,},
                "pvgridcurrent3": {"value": 298,"length": 2,"type": "num","divide": 10,},
                "pvgridpower3": {"value": 302,"length": 4,"type": "num","divide": 10,},
                "totworktime": {"value": 346,"length": 4,"type": "num","divide": 7200,},
                "pvenergytoday": {"value": 354,"length": 4,"type": "num","divide": 10,},
                "pvenergytotal": {"value": 362,"length": 4,"type": "num","divide": 10,},
                "epvtotal": {"value": 370, "length": 4, "type": "num", "divide": 10},
                "epv1today": {"value": 378, "length": 4, "type": "num", "divide": 10},
                "epv1total": {"value": 386, "length": 4, "type": "num", "divide": 10},
                "epv2today": {"value": 394, "length": 4, "type": "num", "divide": 10},
                "epv2total": {"value": 402, "length": 4, "type": "num", "divide": 10},
                "pvtemperature": {"value": 530,"length": 2,"type": "num","divide": 10,},
                "pvipmtemperature": {"value": 546,"length": 2,"type": "num","divide": 10,},
                "pbusvolt": {"value": 550,"length": 2,"type": "num","divide": 10,"incl": "no",},
                "nbusvolt": {"value": 554,"length": 2,"type": "num","divide": 10,"incl": "no",},
            }
        }

        self.recorddict6 = {
            "T06NNNNXSPH": {
                "decrypt": {"value": "True"},
                "datalogserial": {"value": 16,"length": 10,"type": "text","incl": "yes",},
                "pvserial": {"value": 76, "length": 10, "type": "text"},
                "date": {"value": 136, "divide": 10},
                "recortype1": {"value": 150, "length": 2, "type": "num", "incl": "no"},
                "recortype2": {"value": 154, "length": 2, "type": "num", "incl": "no"},
                "pvstatus": {"value": 158, "length": 2, "type": "num"},
                "pvpowerin": {"value": 162, "length": 4, "type": "num", "divide": 10},
                "pv1voltage": {"value": 170, "length": 2, "type": "num", "divide": 10},
                "pv1current": {"value": 174, "length": 2, "type": "num", "divide": 10},
                "pv1watt": {"value": 178, "length": 4, "type": "num", "divide": 10},
                "pv2voltage": {"value": 186, "length": 2, "type": "num", "divide": 10},
                "pv2current": {"value": 190, "length": 2, "type": "num", "divide": 10},
                "pv2watt": {"value": 194, "length": 4, "type": "num", "divide": 10},
                "pvpowerout": {"value": 298, "length": 4, "type": "numx", "divide": 10},
                "pvfrequentie": {"value": 306,"length": 2,"type": "num","divide": 100,},
                "pvgridvoltage": {"value": 310,"length": 2,"type": "num","divide": 10,},
                "pvgridcurrent": {"value": 314,"length": 2,"type": "num","divide": 10,},
                "pvgridpower": {"value": 318, "length": 4, "type": "num", "divide": 10},
                "pvgridvoltage2": {"value": 326,"length": 2,"type": "num","divide": 10,},
                "pvgridcurrent2": {"value": 330,"length": 2,"type": "num","divide": 10,},
                "pvgridpower2": {"value": 334,"length": 4,"type": "num","divide": 10,},
                "pvgridvoltage3": {"value": 342,"length": 2,"type": "num","divide": 10,},
                "pvgridcurrent3": {"value": 346,"length": 2,"type": "num","divide": 10,},
                "pvgridpower3": {"value": 350,"length": 4,"type": "num","divide": 10,},
                "totworktime": {"value": 386,"length": 4,"type": "num","divide": 7200,},
                "eactoday": {"value": 370, "length": 4, "type": "num", "divide": 10},
                "pvenergytoday": {"value": 370,"length": 4,"type": "num","divide": 10,},
                "eactotal": {"value": 378, "length": 4, "type": "num", "divide": 10},
                "epvtotal": {"value": 522, "length": 4, "type": "num", "divide": 10},
                "epv1today": {"value": 394, "length": 4, "type": "num", "divide": 10},
                "epv1total": {"value": 402, "length": 4, "type": "num", "divide": 10},
                "epv2today": {"value": 410, "length": 4, "type": "num", "divide": 10},
                "epv2total": {"value": 418, "length": 4, "type": "num", "divide": 10},
                "pvtemperature": {"value": 530,"length": 2,"type": "num","divide": 10,},
                "pvipmtemperature": {"value": 534,"length": 2,"type": "num","divide": 10,},
                "pvboosttemp": {"value": 538, "length": 2, "type": "num", "divide": 10},
                "bat_dsp": {"value": 546, "length": 2, "type": "num", "divide": 10},
                "pbusvolt": {"value": 550,"length": 2,"type": "num","divide": 10,"incl": "no",},
                "#nbusvolt": {"value": 554,"length": 2,"type": "num","divide": 10,"incl": "no",},
                "#ipf": {"value": 558,"length": 2,"type": "num","divide": 10,"incl": "no",},
                "#realoppercent": {"value": 562,"length": 2,"type": "num","divide": 100,"incl": "no",},
                "#opfullwatt": {"value": 566,"length": 4,"type": "num","divide": 10,"incl": "no",},
                "#deratingmode": {"value": 574,"length": 2,"type": "num","divide": 1,"incl": "no",},
                "eacharge_today": {"value": 606,"length": 4,"type": "num","divide": 10,},
                "eacharge_total": {"value": 614,"length": 4,"type": "num","divide": 10,},
                "batterytype": {"value": 634, "length": 2, "type": "num", "divide": 1},
                "uwsysworkmode": {"value": 666,"length": 2,"type": "num","divide": 1,},
                "systemfaultword0": {"value": 670,"length": 2,"type": "num","divide": 1,},
                "systemfaultword1": {"value": 674,"length": 2,"type": "num","divide": 1,},
                "systemfaultword2": {"value": 678,"length": 2,"type": "num","divide": 1,},
                "systemfaultword3": {"value": 682,"length": 2,"type": "num","divide": 1,},
                "systemfaultword4": {"value": 686,"length": 2,"type": "num","divide": 1,},
                "systemfaultword5": {"value": 690,"length": 2,"type": "num","divide": 1,},
                "systemfaultword6": {"value": 694,"length": 2,"type": "num","divide": 1,},
                "systemfaultword7": {"value": 698,"length": 2,"type": "num","divide": 1,},
                "pdischarge1": {"value": 702, "length": 4, "type": "num", "divide": 10},
                "p1charge1": {"value": 710, "length": 4, "type": "num", "divide": 10},
                "vbat": {"value": 718, "length": 2, "type": "num", "divide": 10},
                "SOC": {"value": 722, "length": 2, "type": "num", "divide": 100},
                "pactouserr": {"value": 726, "length": 4, "type": "num", "divide": 10},
                "#pactousers": {"value": 734,"length": 4,"type": "num","divide": 10,"incl": "no",},
                "#pactousert": {"value": 742,"length": 4,"type": "num","divide": 10,"incl": "no",},
                "pactousertot": {"value": 750,"length": 4,"type": "num","divide": 10,},
                "pactogridr": {"value": 758, "length": 4, "type": "num", "divide": 10},
                "#pactogrids": {"value": 766,"length": 4,"type": "num","divide": 10,"incl": "no",},
                "#pactogridt": {"value": 774,"length": 4,"type": "num","divide": 10,"incl": "no",},
                "pactogridtot": {"value": 782,"length": 4,"type": "num","divide": 10,},
                "plocaloadr": {"value": 790, "length": 4, "type": "num", "divide": 10},
                "#plocaloads": {"value": 798,"length": 4,"type": "num","divide": 10,"incl": "no",},
                "#plocaloadt": {"value": 806,"length": 4,"type": "num","divide": 10,"incl": "no",},
                "plocaloadtot": {"value": 814,"length": 4,"type": "num","divide": 10,},
                "#ipm": {"value": 822,"length": 2,"type": "num","divide": 10,"incl": "no",},
                "#battemp": {"value": 826,"length": 2,"type": "num","divide": 10,"incl": "no",},
                "spdspstatus": {"value": 830, "length": 2, "type": "num", "divide": 10},
                "spbusvolt": {"value": 834, "length": 2, "type": "num", "divide": 10},
                "etouser_tod": {"value": 842, "length": 4, "type": "num", "divide": 10},
                "etouser_tot": {"value": 850, "length": 4, "type": "num", "divide": 10},
                "etogrid_tod": {"value": 858, "length": 4, "type": "num", "divide": 10},
                "etogrid_tot": {"value": 866, "length": 4, "type": "num", "divide": 10},
                "edischarge1_tod": {"value": 874,"length": 4,"type": "num","divide": 10,},
                "edischarge1_tot": {"value": 882,"length": 4,"type": "num","divide": 10,},
                "eharge1_tod": {"value": 890, "length": 4, "type": "num", "divide": 10},
                "eharge1_tot": {"value": 898, "length": 4, "type": "num", "divide": 10},
                "elocalload_tod": {"value": 906,"length": 4,"type": "num","divide": 10,},
                "elocalload_tot": {"value": 914,"length": 4,"type": "num","divide": 10,},
            }
        }

        self.recorddict7 = {
            "T05NNNNSPF": {
                "decrypt": {"value": "True"},
                "datalogserial": {"value": 16,"length": 10,"type": "text","divide": 10,"incl": "yes",},
                "pvserial": {"value": 36, "length": 10, "type": "text"},
                "date": {"value": 56, "divide": 10},
                "recortype1": {"value": 70, "length": 2, "type": "num", "incl": "no"},
                "recortype2": {"value": 74, "length": 2, "type": "num", "incl": "no"},
                "pvstatus": {"value": 78, "length": 2, "type": "num"},
                "vpv1": {"value": 82, "length": 2, "type": "num", "divide": 10},
                "vpv2": {"value": 86, "length": 2, "type": "num", "divide": 10},
                "ppv1": {"value": 90, "length": 4, "type": "num", "divide": 10},
                "ppv2": {"value": 98, "length": 4, "type": "num", "divide": 10},
                "buck1curr": {"value": 106, "length": 2, "type": "num", "divide": 10},
                "buck2curr": {"value": 110, "length": 2, "type": "num", "divide": 10},
                "op_watt": {"value": 114, "length": 4, "type": "num", "divide": 10},
                "pvpowerout": {"value": 114, "length": 4, "type": "num", "divide": 10},
                "op_va": {"value": 122, "length": 4, "type": "num", "divide": 10},
                "acchr_watt": {"value": 130, "length": 4, "type": "num", "divide": 10},
                "acchr_VA": {"value": 138, "length": 4, "type": "num", "divide": 10},
                "bat_Volt": {"value": 146, "length": 2, "type": "num", "divide": 100},
                "batterySoc": {"value": 150, "length": 2, "type": "num", "divide": 1},
                "bus_volt": {"value": 154, "length": 2, "type": "num", "divide": 10},
                "grid_volt": {"value": 158, "length": 2, "type": "num", "divide": 10},
                "line_freq": {"value": 162, "length": 2, "type": "num", "divide": 100},
                "outputvolt": {"value": 166, "length": 2, "type": "num", "divide": 10},
                "pvgridvoltage": {"value": 166,"length": 2,"type": "num","divide": 10,},
                "outputfreq": {"value": 170, "length": 2, "type": "num", "divide": 100},
                "invtemp": {"value": 178, "length": 2, "type": "num", "divide": 10},
                "dcdctemp": {"value": 182, "length": 2, "type": "num", "divide": 10},
                "loadpercent": {"value": 186, "length": 2, "type": "num", "divide": 10},
                "buck1_ntc": {"value": 206, "length": 2, "type": "num", "divide": 10},
                "buck2_ntc": {"value": 210, "length": 2, "type": "num", "divide": 10},
                "OP_Curr": {"value": 214, "length": 2, "type": "num", "divide": 10},
                "Inv_Curr": {"value": 218, "length": 2, "type": "num", "divide": 10},
                "AC_InWatt": {"value": 222, "length": 4, "type": "num", "divide": 10},
                "AC_InVA": {"value": 230, "length": 4, "type": "num", "divide": 10},
                "faultBit": {"value": 238, "length": 2, "type": "num", "divide": 1},
                "warningBit": {"value": 242, "length": 2, "type": "num", "divide": 1},
                "faultValue": {"value": 246, "length": 2, "type": "num", "divide": 1},
                "warningValue": {"value": 250, "length": 2, "type": "num", "divide": 1},
                "constantPowerOK": {"value": 266,"length": 2,"type": "num","divide": 1,},
                "epv1tod": {"value": 270,"length": 4,"type": "num","divide": 10,"incl": "no",},
                "epv1tot": {"value": 278,"length": 4,"type": "num","divide": 10,"incl": "no",},
                "epvToday": {"value": 278, "length": 4, "type": "num", "divide": 10},
                "pvenergytoday": {"value": 278,"length": 4,"type": "num","divide": 10,},
                "epv2tod": {"value": 286,"length": 4,"type": "num","divide": 10,"incl": "no",},
                "epvTotal": {"value": 286, "length": 4, "type": "num", "divide": 10},
                "pvenergytotal": {"value": 286,"length": 4,"type": "num","divide": 10,},
                "epv2tot": {"value": 294,"length": 4,"type": "num","divide": 10,"incl": "no",},
                "eacCharToday": {"value": 310,"length": 4,"type": "num","divide": 10,},
                "eacCharTotal": {"value": 318,"length": 4,"type": "num","divide": 10,},
                "ebatDischarToday": {"value": 326,"length": 4,"type": "num","divide": 10,},
                "ebatDischarTotal": {"value": 334,"length": 4,"type": "num","divide": 10,},
                "eacDischarToday": {"value": 342,"length": 4,"type": "num","divide": 10,},
                "eacDischarTotal": {"value": 350,"length": 4,"type": "num","divide": 10,},
                "ACCharCurr": {"value": 358, "length": 2, "type": "num", "divide": 10},
                "ACDischarWatt": {"value": 362,"length": 4,"type": "num","divide": 10,},
                "ACDischarVA": {"value": 370, "length": 4, "type": "num", "divide": 10},
                "BatDischarWatt": {"value": 378,"length": 4,"type": "num","divide": 10,},
                "BatDischarVA": {"value": 386,"length": 4,"type": "num","divide": 10,},
                "BatWatt": {"value": 394, "length": 4, "type": "numx", "divide": 10},
            }
        }

        self.recorddict8 = {
            "T06NNNNSPF": {
                "decrypt": {"value": "True"},
                "datalogserial": {"value": 16,"length": 10,"type": "text","incl": "yes",},
                "pvserial": {"value": 76, "length": 10, "type": "text"},
                "date": {"value": 136, "divide": 10},
                "recortype1": {"value": 150, "length": 2, "type": "num", "incl": "no"},
                "recortype2": {"value": 154, "length": 2, "type": "num", "incl": "no"},
                "pvstatus": {"value": 158, "length": 2, "type": "num"},
                "vpv1": {"value": 162, "length": 2, "type": "num", "divide": 10},
                "vpv2": {"value": 166, "length": 2, "type": "num", "divide": 10},
                "ppv1": {"value": 170, "length": 4, "type": "num", "divide": 10},
                "ppv2": {"value": 178, "length": 4, "type": "num", "divide": 10},
                "buck1curr": {"value": 186, "length": 2, "type": "num", "divide": 10},
                "buck2curr": {"value": 190, "length": 2, "type": "num", "divide": 10},
                "op_watt": {"value": 194, "length": 4, "type": "num", "divide": 10},
                "pvpowerout": {"value": 194, "length": 4, "type": "num", "divide": 10},
                "op_va": {"value": 204, "length": 4, "type": "num", "divide": 10},
                "acchr_watt": {"value": 210, "length": 4, "type": "num", "divide": 10},
                "acchr_VA": {"value": 218, "length": 4, "type": "num", "divide": 10},
                "bat_Volt": {"value": 226, "length": 2, "type": "num", "divide": 100},
                "batterySoc": {"value": 230, "length": 2, "type": "num", "divide": 1},
                "bus_volt": {"value": 234, "length": 2, "type": "num", "divide": 10},
                "grid_volt": {"value": 238, "length": 2, "type": "num", "divide": 10},
                "line_freq": {"value": 242, "length": 2, "type": "num", "divide": 100},
                "outputvolt": {"value": 246, "length": 2, "type": "num", "divide": 10},
                "pvgridvoltage": {"value": 246,"length": 2,"type": "num","divide": 10,},
                "outputfreq": {"value": 250, "length": 2, "type": "num", "divide": 100},
                "invtemp": {"value": 258, "length": 2, "type": "num", "divide": 10},
                "dcdctemp": {"value": 262, "length": 2, "type": "num", "divide": 10},
                "loadpercent": {"value": 266, "length": 2, "type": "num", "divide": 10},
                "buck1_ntc": {"value": 286, "length": 2, "type": "num", "divide": 10},
                "buck2_ntc": {"value": 290, "length": 2, "type": "num", "divide": 10},
                "OP_Curr": {"value": 294, "length": 2, "type": "num", "divide": 10},
                "Inv_Curr": {"value": 298, "length": 2, "type": "num", "divide": 10},
                "AC_InWatt": {"value": 302, "length": 4, "type": "num", "divide": 10},
                "AC_InVA": {"value": 310, "length": 4, "type": "num", "divide": 10},
                "faultBit": {"value": 318, "length": 2, "type": "num", "divide": 1},
                "warningBit": {"value": 322, "length": 2, "type": "num", "divide": 1},
                "faultValue": {"value": 326, "length": 2, "type": "num", "divide": 1},
                "warningValue": {"value": 330, "length": 2, "type": "num", "divide": 1},
                "constantPowerOK": {"value": 346,"length": 2,"type": "num","divide": 1,},
                "epvtoday": {"value": 358, "length": 4, "type": "num", "divide": 10},
                "pvenergytoday": {"value": 358,"length": 4,"type": "num","divide": 10,},
                "epvtotal": {"value": 366, "length": 4, "type": "num", "divide": 10},
                "eacCharToday": {"value": 390,"length": 4,"type": "num","divide": 10,},
                "eacCharTotal": {"value": 398,"length": 4,"type": "num","divide": 10,},
                "ebatDischarToday": {"value": 406,"length": 4,"type": "num","divide": 10,},
                "ebatDischarTotal": {"value": 414,"length": 4,"type": "num","divide": 10,},
                "eacDischarToday": {"value": 422,"length": 4,"type": "num","divide": 10,},
                "eacDischarTotal": {"value": 430,"length": 4,"type": "num","divide": 10,},
                "ACCharCurr": {"value": 438, "length": 2, "type": "num", "divide": 10},
                "ACDischarWatt": {"value": 442,"length": 4,"type": "num","divide": 10,},
                "ACDischarVA": {"value": 450, "length": 4, "type": "num", "divide": 10},
                "BatDischarWatt": {"value": 458,"length": 4,"type": "num","divide": 10,},
                "BatDischarVA": {"value": 466,"length": 4,"type": "num","divide": 10,},
                "BatWatt": {"value": 474, "length": 4, "type": "numx", "divide": 10},
            }
        }

        self.recorddict9 = {
            "T06NNNNXTL3": {
                "decrypt": {"value": "True"},
                "datalogserial": {"value": 16,"length": 10,"type": "text","incl": "yes",},
                "pvserial": {"value": 76, "length": 10, "type": "text"},
                "date": {"value": 136, "divide": 10},
                "recortype1": {"value": 150, "length": 2, "type": "num", "incl": "no"},
                "recortype2": {"value": 154, "length": 2, "type": "num", "incl": "no"},
                "pvstatus": {"value": 158, "length": 2, "type": "num"},
                "pvpowerin": {"value": 162, "length": 4, "type": "num", "divide": 10},
                "pv1voltage": {"value": 170, "length": 2, "type": "num", "divide": 10},
                "pv1current": {"value": 174, "length": 2, "type": "num", "divide": 10},
                "pv1watt": {"value": 178, "length": 4, "type": "num", "divide": 10},
                "pv2voltage": {"value": 186, "length": 2, "type": "num", "divide": 10},
                "pv2current": {"value": 190, "length": 2, "type": "num", "divide": 10},
                "pv2watt": {"value": 194, "length": 4, "type": "num", "divide": 10},
                "pv3voltage": {"value": 202,"length": 2,"type": "num","divide": 10,"incl": "no",},
                "pv3current": {"value": 206,"length": 2,"type": "num","divide": 10,"incl": "no",},
                "pv3watt": {"value": 210,"length": 4,"type": "num","divide": 10,"incl": "no",},
                "pvpowerout": {"value": 298, "length": 4, "type": "numx", "divide": 10},
                "pvfrequentie": {"value": 306,"length": 2,"type": "num","divide": 100,},
                "pvgridvoltage": {"value": 310,"length": 2,"type": "num","divide": 10,},
                "pvgridcurrent": {"value": 314,"length": 2,"type": "num","divide": 10,},
                "pvgridpower": {"value": 318, "length": 4, "type": "num", "divide": 10},
                "pvgridvoltage2": {"value": 326,"length": 2,"type": "num","divide": 10,},
                "pvgridcurrent2": {"value": 330,"length": 2,"type": "num","divide": 10,},
                "pvgridpower2": {"value": 334,"length": 4,"type": "num","divide": 10,},
                "pvgridvoltage3": {"value": 342,"length": 2,"type": "num","divide": 10,},
                "pvgridcurrent3": {"value": 346,"length": 2,"type": "num","divide": 10,},
                "pvgridpower3": {"value": 350,"length": 4,"type": "num","divide": 10,},
                "Vac_RS": {"value": 358, "length": 2, "type": "num", "divide": 10},
                "Vac_ST": {"value": 362, "length": 2, "type": "num", "divide": 10},
                "Vac_TR": {"value": 366, "length": 2, "type": "num", "divide": 10},
                "pvenergytoday": {"value": 370,"length": 4,"type": "num","divide": 10,},
                "pvenergytotal": {"value": 378,"length": 4,"type": "num","divide": 10,},
                "totworktime": {"value": 386,"length": 4,"type": "num","divide": 7200,},
                "epv1today": {"value": 394, "length": 4, "type": "num", "divide": 10},
                "epv1total": {"value": 402, "length": 4, "type": "num", "divide": 10},
                "epv2today": {"value": 410, "length": 4, "type": "num", "divide": 10},
                "epv2total": {"value": 418, "length": 4, "type": "num", "divide": 10},
                "epvtotal": {"value": 522, "length": 4, "type": "num", "divide": 10},
                "pvtemperature": {"value": 530,"length": 2,"type": "num","divide": 10,},
                "pvipmtemperature": {"value": 534,"length": 2,"type": "num","divide": 10,},
                "pvboottemperature": {"value": 538,"length": 2,"type": "num","divide": 10,},
                "temp4": {"value": 542,"length": 2,"type": "num","divide": 10,"incl": "no",},
                "uwBatVolt_DSP": {"value": 546,"length": 2,"type": "num","divide": 10,},
                "pbusvolt": {"value": 550, "length": 2, "type": "num", "divide": 1},
                "nbusvolt": {"value": 554, "length": 2, "type": "num", "divide": 1},
            }
        }

        self.recorddict10 = {
            "T060120": {
                "decrypt": {"value": "True"},
                "datalogserial": {"value": 16,"length": 10,"type": "text","incl": "yes",},
                "pvserial": {"value": 76, "length": 10, "type": "text"},
                "date": {"value": 136, "divide": 10},
                "voltage_l1": {"value": 160, "length": 4, "type": "num", "divide": 10},
                "voltage_l2": {"value": 168,"length": 4,"type": "num","divide": 10,"incl": "yes",},
                "voltage_l3": {"value": 176,"length": 4,"type": "num","divide": 10,"incl": "yes",},
                "Current_l1": {"value": 184, "length": 4, "type": "num", "divide": 10},
                "Current_l2": {"value": 192,"length": 4,"type": "num","divide": 10,"incl": "yes",},
                "Current_l3": {"value": 200,"length": 4,"type": "num","divide": 10,"incl": "yes",},
                "act_power_l1": {"value": 208,"length": 4,"type": "numx","divide": 10,},
                "act_power_l2": {"value": 216,"length": 4,"type": "numx","divide": 10,"incl": "yes",},
                "act_power_l3": {"value": 224,"length": 4,"type": "numx","divide": 10,"incl": "yes",},
                "app_power_l1": {"value": 232,"length": 4,"type": "numx","divide": 10,},
                "app_power_l2": {"value": 240,"length": 4,"type": "numx","divide": 10,"incl": "yes",},
                "app_power_l3": {"value": 248,"length": 4,"type": "numx","divide": 10,"incl": "yes",},
                "react_power_l1": {"value": 256,"length": 4,"type": "numx","divide": 10,},
                "react_power_l2": {"value": 264,"length": 4,"type": "numx","divide": 10,"incl": "yes",},
                "react_power_l3": {"value": 272,"length": 4,"type": "numx","divide": 10,"incl": "yes",},
                "powerfactor_l1": {"value": 280,"length": 4,"type": "numx","divide": 1000,},
                "powerfactor_l2": {"value": 288,"length": 4,"type": "numx","divide": 1000,"incl": "yes",},
                "powerfactor_l3": {"value": 296,"length": 4,"type": "numx","divide": 1000,"incl": "yes",},
                "pos_rev_act_power": {"value": 304,"length": 4,"type": "numx","divide": 10,},
                "pos_act_power": {"value": 304,"length": 4,"type": "numx","divide": 10,"incl": "yes",},
                "rev_act_power": {"value": 304,"length": 4,"type": "numx","divide": 10,"incl": "yes",},
                "app_power": {"value": 312, "length": 4, "type": "numx", "divide": 10},
                "react_power": {"value": 320,"length": 4,"type": "numx","divide": 10,},
                "powerfactor": {"value": 328,"length": 4,"type": "numx","divide": 1000,},
                "frequency": {"value": 336, "length": 4, "type": "num", "divide": 10},
                "L1-2_voltage": {"value": 344,"length": 4,"type": "num","divide": 10,"incl": "yes",},
                "L2-3_voltage": {"value": 352,"length": 4,"type": "num","divide": 10,"incl": "yes",},
                "L3-1_voltage": {"value": 360,"length": 4,"type": "num","divide": 10,"incl": "yes",},
                "pos_act_energy": {"value": 368,"length": 4,"type": "numx","divide": 10,},
                "rev_act_energy": {"value": 376,"length": 4,"type": "numx","divide": 10,},
                "pos_act_energy_kvar": {"value": 384,"length": 4,"type": "numx","divide": 10,"incl": "no",},
                "rev_act_energy_kvar": {"value": 392,"length": 4,"type": "numx","divide": 10,"incl": "no",},
                "app_energy_kvar": {"value": 400,"length": 4,"type": "numx","divide": 10,"incl": "no",},
                "act_energy_kwh": {"value": 408,"length": 4,"type": "numx","divide": 10,"incl": "no",},
                "react_energy_kvar": {"value": 416,"length": 4,"type": "numx","divide": 10,"incl": "no",},
            }
        }

        self.recorddict11 = {
            "T06501b": {
                "decrypt": {"value": "True"},
                # "rectype"		    	: {"value": "log","type" : "text","incl" : "no"},
                "datalogserial": {"value": 16,"length": 10,"type": "text","incl": "yes",},
                "device": {"value": "SDM630", "type": "def", "incl": "no"},
                # "pvserial"          	: {"value" :36, "length" : 10, "type" : "text"},
                # "recortype1"        	: {"value" :70, "length" : 2, "type" : "num","incl" : "no"},
                # "recortype2"        	: {"value" :74, "length" : 2, "type" : "num","incl" : "no"},
                "logstart": {"value": 96, "type": "def", "incl": "no"},
                "active_energy": {"pos": 1, "type": "log"},
                "reactive_energy": {"pos": 2, "type": "log"},
                "activePowerL1": {"pos": 3, "type": "log"},
                "activePowerL2": {"pos": 4, "type": "log"},
                "activePowerL3": {"pos": 5, "type": "log"},
                "reactivePowerL1": {"pos": 6, "type": "log"},
                "reactivePowerL2": {"pos": 7, "type": "log"},
                "reactivePowerL3": {"pos": 8, "type": "log"},
                "apperentPowerL1": {"pos": 9, "type": "log"},
                "apperentPowerL2": {"pos": 10, "type": "log"},
                "apperentPowerL3": {"pos": 11, "type": "log"},
                "powerFactorL1": {"pos": 12, "type": "log"},
                "powerFactorL2": {"pos": 13, "type": "log"},
                "powerFactorL3": {"pos": 14, "type": "log"},
                "voltageL1": {"pos": 15, "type": "log"},
                "voltageL2": {"pos": 16, "type": "log"},
                "voltageL3": {"pos": 17, "type": "log"},
                "currentL1": {"pos": 18, "type": "log"},
                "currentL2": {"pos": 19, "type": "log"},
                "currentL3": {"pos": 20, "type": "log"},
                "power": {"pos": 21, "type": "log"},
                "active_power": {"pos": 21, "type": "logpos"},
                "reverse_active_power": {"pos": 21, "type": "logneg"},
                "apparent_power": {"pos": 22, "type": "log"},
                "reactive_power": {"pos": 23, "type": "log"},
                "power_factor": {"pos": 24, "type": "log"},
                "frequency": {"pos": 25, "type": "log"},
                "posiActivePower": {"pos": 26, "type": "log"},
                "reverActivePower": {"pos": 27, "type": "log"},
                "posiReactivePower": {"pos": 28, "type": "log"},
                "reverReactivePower": {"pos": 29, "type": "log"},
                "apparentEnergy": {"pos": 30, "type": "log"},
                "totalActiveEnergyL1": {"pos": 31, "type": "log"},
                "totalActiveEnergyL2": {"pos": 32, "type": "log"},
                "totalActiveEnergyL3": {"pos": 33, "type": "log"},
                "totalRectiveEnergyL1": {"pos": 34, "type": "log"},
                "totalRectiveEnergyL2": {"pos": 35, "type": "log"},
                "totalRectiveEnergyL3": {"pos": 36, "type": "log"},
                "total_energy": {"pos": 37, "type": "log"},
                "l1Voltage2": {"pos": 38, "type": "log"},
                "l2Voltage3": {"pos": 39, "type": "log"},
                "l3Voltage1": {"pos": 40, "type": "log"},
                "pos41": {"pos": 41, "type": "log", "incl": "no"},
                "pos42": {"pos": 42, "type": "log", "incl": "no"},
                "pos43": {"pos": 43, "type": "log", "incl": "no"},
                "pos44": {"pos": 44, "type": "log", "incl": "no"},
                "pos45": {"pos": 45, "type": "log", "incl": "no"},
                "pos46": {"pos": 46, "type": "log", "incl": "no"},
                "pos47": {"pos": 47, "type": "log", "incl": "no"},
                "pos48": {"pos": 48, "type": "log", "incl": "no"},
                "pos49": {"pos": 49, "type": "log", "incl": "no"},
                "pos50": {"pos": 50, "type": "log", "incl": "no"},
                "pos51": {"pos": 51, "type": "log", "incl": "no"},
                "pos52": {"pos": 52, "type": "log", "incl": "no"},
                "pos53": {"pos": 53, "type": "log", "incl": "no"},
                "pos54": {"pos": 54, "type": "log", "incl": "no"},
                "pos55": {"pos": 55, "type": "log", "incl": "no"},
                "pos56": {"pos": 56, "type": "log", "incl": "no"},
                "pos57": {"pos": 57, "type": "log", "incl": "no"},
                "pos58": {"pos": 58, "type": "log", "incl": "no"},
                "pos59": {"pos": 59, "type": "log", "incl": "no"},
                "pos60": {"pos": 60, "type": "log", "incl": "no"},
                "pos61": {"pos": 61, "type": "log", "incl": "no"},
                "pos62": {"pos": 62, "type": "log", "incl": "no"},
                "pos63": {"pos": 63, "type": "log", "incl": "no"},
                "pos64": {"pos": 64, "type": "log", "incl": "no"},
                "pos65": {"pos": 65, "type": "log", "incl": "no"},
                "pos66": {"pos": 66, "type": "log", "incl": "no"},
            }
        }

        self.recorddict12 = {
            "T05NNNNXSPH": {
                "decrypt": {"value": "True"},
                "datalogserial": {"value": 16,"length": 10,"type": "text","incl": "yes",},
                "pvserial": {"value": 36, "length": 10, "type": "text"},
                "date": {"value": 56, "divide": 10},
                "recortype1": {"value": 70, "length": 2, "type": "num", "incl": "no"},
                "recortype2": {"value": 74, "length": 2, "type": "num", "incl": "no"},
                "pvstatus": {"value": 78, "length": 2, "type": "num"},
                "pvpowerin": {"value": 82, "length": 4, "type": "num", "divide": 10},
                "pv1voltage": {"value": 90, "length": 2, "type": "num", "divide": 10},
                "pv1current": {"value": 94, "length": 2, "type": "num", "divide": 10},
                "pv1watt": {"value": 98, "length": 4, "type": "num", "divide": 10},
                "pv2voltage": {"value": 106, "length": 2, "type": "num", "divide": 10},
                "pv2current": {"value": 110, "length": 2, "type": "num", "divide": 10},
                "pv2watt": {"value": 114, "length": 4, "type": "num", "divide": 10},
                "pvpowerout": {"value": 218, "length": 4, "type": "numx", "divide": 10},
                "pvfrequentie": {"value": 226,"length": 2,"type": "num","divide": 100,},
                "pvgridvoltage": {"value": 230,"length": 2,"type": "num","divide": 10,},
                "pvgridcurrent": {"value": 234,"length": 2,"type": "num","divide": 10,},
                "pvgridpower": {"value": 238, "length": 4, "type": "num", "divide": 10},
                "pvgridvoltage2": {"value": 246,"length": 2,"type": "num","divide": 10,},
                "pvgridcurrent2": {"value": 250,"length": 2,"type": "num","divide": 10,},
                "pvgridpower2": {"value": 254,"length": 4,"type": "num","divide": 10,},
                "pvgridvoltage3": {"value": 262,"length": 2,"type": "num","divide": 10,},
                "pvgridcurrent3": {"value": 266,"length": 2,"type": "num","divide": 10,},
                "pvgridpower3": {"value": 270,"length": 4,"type": "num","divide": 10,},
                "totworktime": {"value": 306,"length": 4,"type": "num","divide": 7200,},
                "eactoday": {"value": 290, "length": 4, "type": "num", "divide": 10},
                "pvenergytoday": {"value": 290,"length": 4,"type": "num","divide": 10,},
                "eactotal": {"value": 298, "length": 4, "type": "num", "divide": 10},
                "epvtotal": {"value": 442, "length": 4, "type": "num", "divide": 10},
                "epv1today": {"value": 314, "length": 4, "type": "num", "divide": 10},
                "epv1total": {"value": 322, "length": 4, "type": "num", "divide": 10},
                "epv2today": {"value": 330, "length": 4, "type": "num", "divide": 10},
                "epv2total": {"value": 338, "length": 4, "type": "num", "divide": 10},
                "pvtemperature": {"value": 450,"length": 2,"type": "num","divide": 10,},
                "pvipmtemperature": {"value": 454,"length": 2,"type": "num","divide": 10,},
                "pvboosttemp": {"value": 458, "length": 2, "type": "num", "divide": 10},
                "bat_dsp": {"value": 466, "length": 2, "type": "num", "divide": 10},
                "pbusvolt": {"value": 470,"length": 2,"type": "num","divide": 10,"incl": "no",},
                "#nbusvolt": {"value": 474,"length": 2,"type": "num","divide": 10,"incl": "no",},
                "#ipf": {"value": 478,"length": 2,"type": "num","divide": 10,"incl": "no",},
                "#realoppercent": {"value": 482,"length": 2,"type": "num","divide": 100,"incl": "no",},
                "#opfullwatt": {"value": 486,"length": 4,"type": "num","divide": 10,"incl": "no",},
                "#deratingmode": {"value": 494,"length": 2,"type": "num","divide": 1,"incl": "no",},
                "eacharge_today": {"value": 526,"length": 4,"type": "num","divide": 10,},
                "eacharge_total": {"value": 534,"length": 4,"type": "num","divide": 10,},
                "batterytype": {"value": 554, "length": 2, "type": "num", "divide": 1},
                "uwsysworkmode": {"value": 586,"length": 2,"type": "num","divide": 1,},
                "systemfaultword0": {"value": 590,"length": 2,"type": "num","divide": 1,},
                "systemfaultword1": {"value": 594,"length": 2,"type": "num","divide": 1,},
                "systemfaultword2": {"value": 588,"length": 2,"type": "num","divide": 1,},
                "systemfaultword3": {"value": 602,"length": 2,"type": "num","divide": 1,},
                "systemfaultword4": {"value": 606,"length": 2,"type": "num","divide": 1,},
                "systemfaultword5": {"value": 610,"length": 2,"type": "num","divide": 1,},
                "systemfaultword6": {"value": 614,"length": 2,"type": "num","divide": 1,},
                "systemfaultword7": {"value": 618,"length": 2,"type": "num","divide": 1,},
                "pdischarge1": {"value": 622, "length": 4, "type": "num", "divide": 10},
                "p1charge1": {"value": 630, "length": 4, "type": "num", "divide": 10},
                "vbat": {"value": 738, "length": 2, "type": "num", "divide": 10},
                "SOC": {"value": 742, "length": 2, "type": "num", "divide": 100},
                "pactouserr": {"value": 746, "length": 4, "type": "num", "divide": 10},
                "#pactousers": {"value": 654,"length": 4,"type": "num","divide": 10,"incl": "no",},
                "#pactousert": {"value": 662,"length": 4,"type": "num","divide": 10,"incl": "no",},
                "pactousertot": {"value": 670,"length": 4,"type": "num","divide": 10,},
                "pactogridr": {"value": 678, "length": 4, "type": "num", "divide": 10},
                "#pactogrids": {"value": 686,"length": 4,"type": "num","divide": 10,"incl": "no",},
                "#pactogridt": {"value": 694,"length": 4,"type": "num","divide": 10,"incl": "no",},
                "pactogridtot": {"value": 702,"length": 4,"type": "num","divide": 10,},
                "plocaloadr": {"value": 710, "length": 4, "type": "num", "divide": 10},
                "#plocaloads": {"value": 718,"length": 4,"type": "num","divide": 10,"incl": "no",},
                "#plocaloadt": {"value": 726,"length": 4,"type": "num","divide": 10,"incl": "no",},
                "plocaloadtot": {"value": 734,"length": 4,"type": "num","divide": 10,},
                "#ipm": {"value": 742,"length": 2,"type": "num","divide": 10,"incl": "no",},
                "#battemp": {"value": 746,"length": 2,"type": "num","divide": 10,"incl": "no",},
                "spdspstatus": {"value": 750, "length": 2, "type": "num", "divide": 10},
                "spbusvolt": {"value": 754, "length": 2, "type": "num", "divide": 10},
                "etouser_tod": {"value": 762, "length": 4, "type": "num", "divide": 10},
                "etouser_tot": {"value": 770, "length": 4, "type": "num", "divide": 10},
                "etogrid_tod": {"value": 778, "length": 4, "type": "num", "divide": 10},
                "etogrid_tot": {"value": 786, "length": 4, "type": "num", "divide": 10},
                "edischarge1_tod": {"value": 794,"length": 4,"type": "num","divide": 10,},
                "edischarge1_tot": {"value": 802,"length": 4,"type": "num","divide": 10,},
                "eharge1_tod": {"value": 810, "length": 4, "type": "num", "divide": 10},
                "eharge1_tot": {"value": 818, "length": 4, "type": "num", "divide": 10},
                "elocalload_tod": {"value": 826,"length": 4,"type": "num","divide": 10,},
                "elocalload_tot": {"value": 834,"length": 4,"type": "num","divide": 10,},
            }
        }
        # fmt: on

        self.recorddict.update(self.recorddict1)
        self.recorddict.update(self.recorddict2)
        self.recorddict.update(self.recorddict3)
        self.recorddict.update(self.recorddict4)
        self.recorddict.update(self.recorddict5)
        self.recorddict.update(self.recorddict6)
        self.recorddict.update(self.recorddict7)
        self.recorddict.update(self.recorddict8)
        self.recorddict.update(self.recorddict9)
        self.recorddict.update(self.recorddict10)
        self.recorddict.update(self.recorddict11)
        self.recorddict.update(self.recorddict12)  # T05NNNNXSPH
        f = []
        pr("\nGrott process json layout files")
        for _, _, filenames in os.walk("."):
            f.extend(filenames)
            break
        for x in f:
            if x[0].lower() == "t" and x[-len(".json") :].lower() == ".json":
                pr(x)
                with open(x, "r", encoding="utf-8") as json_file:
                    dicttemp = json.load(json_file)
                    self.recorddict.update(dicttemp)

        if self.verbose:
            pr("\nGrott layout records loaded")
            for key, value in self.recorddict.items():
                pr(key, " : ")
                pr(value)

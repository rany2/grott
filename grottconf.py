"""
grottconf  process command parameter and settings file
Updated: 2023-12-04
Version 2.8.3
"""

import argparse
import configparser as cp
import json
import os
from collections import defaultdict

from influxdb_client import InfluxDBClient
from influxdb_client.client.write_api import \
    ASYNCHRONOUS as INFLUXDB_ASYNCHRONOUS

from grotthelpers import pr

_UNSET = object()


def get_option_environ(option):
    return os.getenv(f"g{option}")


class CustomConfigParser(cp.ConfigParser):
    def __init__(self, *args, **kwargs):
        self.section_opt_pairing = defaultdict(list)
        return super().__init__(*args, **kwargs)

    def has_option(self, section, option, confvar=_UNSET, environ_key=_UNSET) -> bool:
        if confvar is _UNSET:
            confvar = option
        self.section_opt_pairing[section].append((option, confvar))
        if get_option_environ(option if environ_key is _UNSET else environ_key):
            return True
        return super().has_option(section, option)

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
        self.registerreadtimeout = 15.0
        self.registerwritetimeout = 15.0
        self.sendseq = 1
        self.serverforward = False
        self.httptimeout = 10.0
        self.forwardretry = 1
        self.forwardtimeout = 5.0
        self.senddelay = 0.01

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
        self.pvuplimit = 5

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
        if config.has_option("Generic", "minrecl"):
            self.minrecl = config.getint("Generic", "minrecl")
        if config.has_option("Generic", "verbose"):
            self.verbose = config.getboolean("Generic", "verbose")
        if config.has_option("Generic", "includeall"):
            self.includeall = config.getboolean("Generic", "includeall")
        if config.has_option("Generic", "invtype"):
            self.invtype = config.get("Generic", "invtype")
        if config.has_option("Generic", "invtypemap"):
            self.invtypemap = eval(config.get("Generic", "invtypemap"))
        if config.has_option("Generic", "inverterid"):
            self.inverterid = config.get("Generic", "inverterid")
        if config.has_option("Generic", "noipf"):
            self.noipf = config.getboolean("Generic", "noipf")
        if config.has_option("Generic", "time", "gtime"):
            self.gtime = config.get("Generic", "time")
        if config.has_option("Generic", "sendbuf"):
            self.sendbuf = config.getboolean("Generic", "sendbuf")
        if config.has_option("Generic", "timezone", "tmzone"):
            self.tmzone = config.get("Generic", "timezone")
        if config.has_option("Generic", "mode"):
            self.mode = config.get("Generic", "mode")
        if config.has_option("Generic", "ip", "grottip", environ_key="grottip"):
            self.grottip = config.get("Generic", "ip", environ_key="grottip")
        if config.has_option("Generic", "port", "grottport", environ_key="grottport"):
            self.grottport = config.getint("Generic", "port", environ_key="grottport")
        if config.has_option("Generic", "timeout"):
            self.timeout = config.getfloat("Generic", "timeout")

        if config.has_option("Growatt", "ip", "growattip", environ_key="growattip"):
            self.growattip = config.get("Growatt", "ip", environ_key="growattip")
        if config.has_option(
            "Growatt", "port", "growattport", environ_key="growattport"
        ):
            self.growattport = config.getint(
                "Growatt", "port", environ_key="growattport"
            )
        if config.has_option("Server", "httpip", "httphost"):
            self.httphost = config.get("Server", "httpip")
        if config.has_option("Server", "httpport"):
            self.httpport = config.getint("Server", "httpport")
        if config.has_option("Server", "httptoken"):
            self.httptoken = config.get("Server", "httptoken")

        if config.has_option("Server", "httptimeout"):
            self.httptimeout = config.getfloat("Server", "httptimeout")
        if config.has_option("Server", "registerreadtimeout"):
            self.registerreadtimeout = config.getfloat("Server", "registerreadtimeout")
        if config.has_option("Server", "registerwritetimeout"):
            self.registerwritetimeout = config.getfloat("Server", "registerwritetimeout")
        if config.has_option("Server", "sendseq"):
            self.sendseq = config.getint("Server", "sendseq")
        if config.has_option("Server", "serverforward"):
            self.serverforward = config.getboolean("Server", "serverforward")
        if config.has_option("Server", "forwardretry"):
            self.forwardretry = config.getint("Server", "forwardretry")
        if config.has_option("Server", "forwardtimeout"):
            self.forwardtimeout = config.getfloat("Server", "forwardtimeout")
        if config.has_option("Server", "senddelay"):
            self.senddelay = config.getfloat("Server", "senddelay")

        if config.has_option("MQTT", "nomqtt"):
            self.nomqtt = config.getboolean("MQTT", "nomqtt")
        if config.has_option("MQTT", "ip", "mqttip", environ_key="mqttip"):
            self.mqttip = config.get("MQTT", "ip", environ_key="mqttip")
        if config.has_option("MQTT", "port", "mqttport", environ_key="mqttport"):
            self.mqttport = config.getint("MQTT", "port", environ_key="mqttport")
        if config.has_option("MQTT", "topic", "mqtttopic", environ_key="mqtttopic"):
            self.mqtttopic = config.get("MQTT", "topic", environ_key="mqtttopic")
        if config.has_option(
            "MQTT",
            "deviceidintopic",
            "mqttdeviceidintopic",
            environ_key="mqttdeviceidintopic",
        ):
            self.mqttdeviceidintopic = config.getboolean(
                "MQTT", "deviceidintopic", environ_key="mqttdeviceidintopic"
            )
        if config.has_option("MQTT", "mtopic", "mqttmtopic", environ_key="mqttmtopic"):
            self.mqttmtopic = config.getboolean(
                "MQTT", "mtopic", environ_key="mqttmtopic"
            )
        if config.has_option(
            "MQTT", "mtopicname", "mqttmtopicname", environ_key="mqttmtopicname"
        ):
            self.mqttmtopicname = config.get(
                "MQTT", "mtopicname", environ_key="mqttmtopicname"
            )
        if config.has_option("MQTT", "retain", "mqttretain", environ_key="mqttretain"):
            self.mqttretain = config.getboolean(
                "MQTT", "retain", environ_key="mqttretain"
            )
        if config.has_option("MQTT", "auth", "mqttauth", environ_key="mqttauth"):
            self.mqttauth = config.getboolean("MQTT", "auth", environ_key="mqttauth")
        if config.has_option("MQTT", "user", "mqttuser", environ_key="mqttuser"):
            self.mqttuser = config.get("MQTT", "user", environ_key="mqttuser")
        if config.has_option("MQTT", "password", "mqttpsw", environ_key="mqttpassword"):
            self.mqttpsw = config.get("MQTT", "password", environ_key="mqttpassword")

        if config.has_option("PVOutput", "pvoutput"):
            self.pvoutput = config.getboolean("PVOutput", "pvoutput")
        if config.has_option("PVOutput", "pvtemp"):
            self.pvtemp = config.getboolean("PVOutput", "pvtemp")
        if config.has_option("PVOutput", "pvdisv1"):
            self.pvdisv1 = config.getboolean("PVOutput", "pvdisv1")
        if config.has_option("PVOutput", "pvinverters"):
            self.pvinverters = config.getint("PVOutput", "pvinverters")
        if config.has_option("PVOutput", "apikey", "pvapikey"):
            self.pvapikey = config.get("PVOutput", "apikey", environ_key="pvapikey")
        if config.has_option("PVOutput", "pvuplimit"):
            self.pvuplimit = config.getint("PVOutput", "pvuplimit")
        # if more inverter are installed at the same interface (shinelink) get systemids
        # if self.pvinverters > 1 :
        for x in range(self.pvinverters + 1):
            if x == 0:
                continue

            if config.has_option("PVOutput", f"systemid{x}", f"pvsystemid{x}"):
                self.pvsystemid[x] = config.get("PVOutput", f"systemid{x}")
            if config.has_option("PVOutput", f"inverterid{x}", f"pvinverterid{x}"):
                self.pvinverterid[x] = config.get("PVOutput", f"inverterid{x}")
        if self.pvinverters == 1:
            if config.has_option("PVOutput", "systemid", "pvsystemid1"):
                self.pvsystemid[1] = config.get("PVOutput", "systemid")
        if config.has_option("PVOutput", "pvtimeout"):
            self.pvtimeout = config.getfloat("PVOutput", "pvtimeout")

        # INFLUX
        if config.has_option("influx", "influx"):
            self.influx = config.getboolean("influx", "influx")
        if config.has_option("influx", "url", "ifurl", environ_key="ifurl"):
            self.ifurl = config.get("influx", "url", environ_key="ifurl")
        if config.has_option("influx", "org", "iforg", environ_key="iforg"):
            self.iforg = config.get("influx", "org", environ_key="iforg")
        if config.has_option("influx", "bucket", "ifbucket", environ_key="ifbucket"):
            self.ifbucket = config.get("influx", "bucket", environ_key="ifbucket")
        if config.has_option("influx", "token", "iftoken", environ_key="iftoken"):
            self.iftoken = config.get("influx", "token", environ_key="iftoken")

        # extension
        if config.has_option("extension", "extension"):
            self.extension = config.getboolean("extension", "extension")
        if config.has_option("extension", "extname"):
            self.extname = config.get("extension", "extname")
        if config.has_option("extension", "extvar"):
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
                "SOC": {"value": 722, "length": 2, "type": "num", "divide": 1},
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
                "SOC": {"value": 742, "length": 2, "type": "num", "divide": 1},
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
        self.recorddict13 = {"T06NNNNXSPA": {
            "decrypt"           : {"value" :"True"},
            "datalogserial"     : {"value" :16, "length" : 10, "type" : "text","incl" : "yes"},
            "pvserial"          : {"value" :76, "length" : 10, "type" : "text"},
            "date"              : {"value" :136, "divide" : 10}, 
            "group1start"         : {"value" :150, "length" : 2, "type" : "num","incl" : "no"}, 
            "group1end"           : {"value" :154, "length" : 2, "type" : "num","incl" : "no"}, 
            "pvstatus"           : {"value" :158, "length" : 2, "type" : "num"},   
            "uwsysworkmode"      : {"value" :666, "length" : 2, "type" : "num", "divide" : 1},
            "systemfaultword0"   : {"value" :162, "length" : 2, "type" : "num", "divide" : 1},
            "systemfaultword1"   : {"value" :166, "length" : 2, "type" : "num", "divide" : 1},
            "systemfaultword2"   : {"value" :170, "length" : 2, "type" : "num", "divide" : 1},
            "systemfaultword3"   : {"value" :174, "length" : 2, "type" : "num", "divide" : 1},
            "systemfaultword4"   : {"value" :178, "length" : 2, "type" : "num", "divide" : 1},
            "systemfaultword5"   : {"value" :182, "length" : 2, "type" : "num", "divide" : 1},
            "systemfaultword6"   : {"value" :186, "length" : 2, "type" : "num", "divide" : 1},
            "systemfaultword7"   : {"value" :190, "length" : 2, "type" : "num", "divide" : 1},
            "pdischarge1"        : {"value" :194, "length" : 4, "type" : "num", "divide" : 10}, 
            "pcharge1"           : {"value" :202, "length" : 4, "type" : "num", "divide" : 10}, 
            "vbat"               : {"value" :210, "length" : 2, "type" : "num", "divide" : 10}, 
            "SOC"                : {"value" :214, "length" : 2, "type" : "num", "divide" : 100}, 
            "pactouserr"         : {"value" :218, "length" : 4, "type" : "num", "divide" : 10}, 
            "pactousers"         : {"value" :226, "length" : 4, "type" : "num", "divide" : 10}, 
            "pactousert"         : {"value" :234, "length" : 4, "type" : "num", "divide" : 10}, 
            "pactousertot"       : {"value" :242, "length" : 4, "type" : "num", "divide" : 10},
            "pactogridr"         : {"value" :250, "length" : 4, "type" : "num", "divide" : 10}, 
            "pactogrids "        : {"value" :258, "length" : 4, "type" : "num", "divide" : 10}, 
            "pactogrid t"        : {"value" :266, "length" : 4, "type" : "num", "divide" : 10}, 
            "pactogridtot"       : {"value" :274, "length" : 4, "type" : "num", "divide" : 10}, 
            "plocaloadr"         : {"value" :282, "length" : 4, "type" : "num", "divide" : 10}, 
            "plocaloads"        : {"value" :290, "length" : 4, "type" : "num", "divide" : 10}, 
            "plocaloadt"        : {"value" :298, "length" : 4, "type" : "num", "divide" : 10}, 
            "plocaloadtot"       : {"value" :306, "length" : 4, "type" : "num", "divide" : 10},   
            "ipm"                : {"value" :314, "length" : 2, "type" : "num", "divide" : 10},   
            "battemp "           : {"value" :318, "length" : 2, "type" : "num", "divide" : 10},   
            "spdspstatus"        : {"value" :322, "length" : 2, "type" : "num", "divide" : 10},   
            "spbusvolt"          : {"value" :328, "length" : 2, "type" : "num", "divide" : 10},
            "etouser_tod"        : {"value" :334, "length" : 4, "type" : "num", "divide" : 10}, 
            "etouser_tot"        : {"value" :342, "length" : 4, "type" : "num", "divide" : 10}, 
            "etogrid_tod"        : {"value" :350, "length" : 4, "type" : "num", "divide" : 10}, 
            "etogrid_tot"        : {"value" :358, "length" : 4, "type" : "num", "divide" : 10},
            "edischarge1_tod"    : {"value" :366, "length" : 4, "type" : "num", "divide" : 10}, 
            "edischarge1_tot"    : {"value" :374, "length" : 4, "type" : "num", "divide" : 10}, 
            "eharge1_tod"        : {"value" :382, "length" : 4, "type" : "num", "divide" : 10}, 
            "eharge1_tot"        : {"value" :390, "length" : 4, "type" : "num", "divide" : 10}, 
            "elocalload_tod"     : {"value" :398, "length" : 4, "type" : "num", "divide" : 10}, 
            "elocalload_tot"     : {"value" :406, "length" : 4, "type" : "num", "divide" : 10}, 
            "dwexportlimitap"    : {"value" :414, "length" : 4, "type" : "num", "divide" : 10}, 
            "epsfac"             : {"value" :426, "length" : 2, "type" : "num", "divide" : 100}, 
            "epsvac1"            : {"value" :430, "length" : 2, "type" : "num", "divide" : 10}, 
            "epsiac1"            : {"value" :434, "length" : 2, "type" : "num", "divide" : 10}, 
            "epspac1"            : {"value" :438, "length" : 4, "type" : "num", "divide" : 10}, 
            "epsvac2"            : {"value" :446, "length" : 2, "type" : "num", "divide" : 10}, 
            "epsiac2"            : {"value" :450, "length" : 2, "type" : "num", "divide" : 10}, 
            "epspac2"            : {"value" :454, "length" : 4, "type" : "num", "divide" : 10}, 
            "epsvac3"            : {"value" :462, "length" : 2, "type" : "num", "divide" : 10}, 
            "epsiac3"            : {"value" :466, "length" : 2, "type" : "num", "divide" : 10}, 
            "epspac3"            : {"value" :470, "length" : 4, "type" : "num", "divide" : 10}, 
            "loadpercent"        : {"value" :478, "length" : 2, "type" : "num", "divide" : 1}, 
            "pf"                 : {"value" :482, "length" : 2, "type" : "num", "divide" : 10}, 
            "bmsstatusold"       : {"value" :486, "length" : 2, "type" : "num", "divide" : 1}, 
            "bmsstatus"          : {"value" :490, "length" : 2, "type" : "num", "divide" : 1}, 
            "bmserrorold"        : {"value" :494, "length" : 2, "type" : "num", "divide" : 1}, 
            "bmserror"           : {"value" :498, "length" : 2, "type" : "num", "divide" : 1}, 
            "bmssoc"             : {"value" :502, "length" : 2, "type" : "num", "divide" : 1}, 
            "bmsbatteryvolt"     : {"value" :506, "length" : 2, "type" : "num", "divide" : 100}, 
            "bmsbatterycurr"     : {"value" :510, "length" : 2, "type" : "num", "divide" : 100}, 
            "bmsbatterytemp"     : {"value" :514, "length" : 2, "type" : "num", "divide" : 100}, 
            "bmsmaxcurr"         : {"value" :518, "length" : 2, "type" : "num", "divide" : 100}, 
            "bmsgaugerm"         : {"value" :522, "length" : 2, "type" : "num", "divide" : 1}, 
            "bmsgaugefcc"        : {"value" :526, "length" : 2, "type" : "num", "divide" : 1}, 
            "bmsfw"              : {"value" :530, "length" : 2, "type" : "num", "divide" : 1}, 
            "bmsdeltavolt"       : {"value" :534, "length" : 2, "type" : "num", "divide" : 1}, 
            "bmscyclecnt"        : {"value" :538, "length" : 2, "type" : "num", "divide" : 1}, 
            "bmssoh"             : {"value" :542, "length" : 2, "type" : "num", "divide" : 1}, 
            "bmsconstantvolt"    : {"value" :546, "length" : 2, "type" : "num", "divide" : 100}, 
            "bmswarninfoold"     : {"value" :550, "length" : 2, "type" : "num", "divide" : 1}, 
            "bmswarninfo"        : {"value" :554, "length" : 2, "type" : "num", "divide" : 1}, 
            "bmsgaugeiccurr"     : {"value" :558, "length" : 2, "type" : "num", "divide" : 1}, 
            "bmsmcuversion"      : {"value" :562, "length" : 2, "type" : "num", "divide" : 100}, 
            "bmsgaugeversion"    : {"value" :566, "length" : 2, "type" : "num", "divide" : 1}, 
            "bmswgaugefrversionl": {"value" :570, "length" : 2, "type" : "num", "divide" : 1}, 
            "bmswgaugefrversionh": {"value" :574, "length" : 2, "type" : "num", "divide" : 1}, 
            "bmsbmsinfo"         : {"value" :578, "length" : 2, "type" : "num", "divide" : 1}, 
            "bmspackinfo"        : {"value" :582, "length" : 2, "type" : "num", "divide" : 1}, 
            "bmsusingcap"        : {"value" :586, "length" : 2, "type" : "num", "divide" : 1}, 
            "bmscell1volt"       : {"value" :590, "length" : 2, "type" : "num", "divide" : 100}, 
            "bmscell2volt"       : {"value" :594, "length" : 2, "type" : "num", "divide" : 100}, 
            "bmscell3volt"       : {"value" :598, "length" : 2, "type" : "num", "divide" : 100}, 
            "bmscell4volt"       : {"value" :602, "length" : 2, "type" : "num", "divide" : 100}, 
            "bmscell5volt"       : {"value" :606, "length" : 2, "type" : "num", "divide" : 100}, 
            "bmscell6volt"       : {"value" :610, "length" : 2, "type" : "num", "divide" : 100}, 
            "bmscell7volt"       : {"value" :614, "length" : 2, "type" : "num", "divide" : 100}, 
            "bmscell8volt"       : {"value" :618, "length" : 2, "type" : "num", "divide" : 100}, 
            "bmscell9volt"       : {"value" :622, "length" : 2, "type" : "num", "divide" : 100}, 
            "bmscell10volt"      : {"value" :626, "length" : 2, "type" : "num", "divide" : 100}, 
            "bmscell11volt"      : {"value" :630, "length" : 2, "type" : "num", "divide" : 100}, 
            "bmscell12volt"      : {"value" :634, "length" : 2, "type" : "num", "divide" : 100}, 
            "bmscell13volt"      : {"value" :638, "length" : 2, "type" : "num", "divide" : 100}, 
            "bmscell14volt"      : {"value" :642, "length" : 2, "type" : "num", "divide" : 100}, 
            "bmscell15volt"      : {"value" :646, "length" : 2, "type" : "num", "divide" : 100}, 
            "bmscell16volt"      : {"value" :650, "length" : 2, "type" : "num", "divide" : 100}, 
            "acchargeenergytodayh": {"value" :654, "length" : 2, "type" : "num", "divide" : 10,"incl" : "no"},                 #deze is een beetjevreemd omdat de high en Low over groepem heen gedefinieerd zijn en uit elkaar liggen
            "group2start"        : {"value" :658, "length" : 2, "type" : "num","incl" : "no"}, 
            "group2end"          : {"value" :662, "length" : 2, "type" : "num","incl" : "no"},  
            "acchargeenergytoday": {"value" :666, "length" : 2, "type" : "num", "divide" : 1},                                 # vooralsnog ervan uitgegaan dat low alleen genoeg is!    
            "acchargeenergytotal": {"value" :670, "length" : 4, "type" : "num", "divide" : 1},
            "acchargepower"      : {"value" :678,"length" : 4, "type" : "num", "divide" : 1},
            "70%_invpoweradjust" : {"value" :686,"length" : 2, "type" : "num", "divide" : 1},
            "extraacpowertogrid" : {"value" :690, "length" : 4, "type" : "num", "divide" : 1},
            "eextratoday"        : {"value" :698, "length" : 4, "type" : "num", "divide" : 10},
            "eextratotal"        : {"value" :704, "length" : 4, "type" : "num", "divide" : 10},
            "esystemtoday"       : {"value" :712, "length" : 4, "type" : "num", "divide" : 10},
            "esystemtotal"       : {"value" :720, "length" : 4, "type" : "num", "divide" : 10},
            "group3start"        : {"value" :1166, "length" : 2, "type" : "num","incl" : "no"}, 
            "group3end"          : {"value" :1170, "length" : 2, "type" : "num","incl" : "no"},
            "inverterstatus"     : {"value" :1174, "length" : 2, "type" : "num", "divide" : 1}, 
            "pacs"               : {"value" :1314, "length" : 4, "type" : "numx", "divide" : 10}, 
            "fac"                : {"value" :1322, "length" : 2, "type" : "num", "divide" : 100}, 
            "vac1"               : {"value" :1326, "length" : 2, "type" : "num", "divide" : 10}, 
            "iac1"               : {"value" :1330, "length" : 2, "type" : "num", "divide" : 10}, 
            "pac1"               : {"value" :1334, "length" : 4, "type" : "num", "divide" : 10},            
            "eactoday"           : {"value" :1386, "length" : 4, "type" : "num", "divide" : 10}, 
            "eactot"             : {"value" :1394, "length" : 4, "type" : "num", "divide" : 10}, 
            "timetotal"          : {"value" :1402, "length" : 4, "type" : "num", "divide" : 7200}, 
            "Temp1"              : {"value" :1546, "length" : 2, "type" : "num", "divide" : 10}, 
            "Temp2"              : {"value" :1550, "length" : 2, "type" : "num", "divide" : 10}, 
            "Temp3"              : {"value" :1554, "length" : 2, "type" : "num", "divide" : 10}, 
            "Temp4"              : {"value" :1558, "length" : 2, "type" : "num", "divide" : 10}, 
            "uwbatvoltdsp"       : {"value" :1562, "length" : 2, "type" : "num", "divide" : 10}, 
            "pbusvoltage"        : {"value" :1566, "length" : 2, "type" : "num", "divide" : 10}, 
            "nbusvoltage"        : {"value" :1570, "length" : 2, "type" : "num", "divide" : 10}, 
            "remotectrlen"       : {"value" :1574, "length" : 2, "type" : "num", "divide" : 1}, 
            "remotectrlpower"    : {"value" :1578, "length" : 2, "type" : "num", "divide" : 1}, 
            "extraacpowertogrid" : {"value" :1582, "length" : 4, "type" : "num", "divide" : 10}, 
            "eextratoday"        : {"value" :1590, "length" : 4, "type" : "num", "divide" : 10}, 
            "eextratotal"        : {"value" :1598, "length" : 4, "type" : "num", "divide" : 10}, 
            "esystemtoday"       : {"value" :1606, "length" : 4, "type" : "num", "divide" : 10}, 
            "esystemtotal"       : {"value" :1614, "length" : 4, "type" : "num", "divide" : 10}, 
            "eacchargetoday"     : {"value" :1622, "length" : 4, "type" : "num", "divide" : 10},
            "eacchargetotal"     : {"value" :1630, "length" : 4, "type" : "num", "divide" : 10}, 
            "acchargepower"      : {"value" :1638, "length" : 4, "type" : "num", "divide" : 10}, 
            "priority"           : {"value" :1646, "length" : 2, "type" : "num", "divide" : 1}, 
            "batterytype"        : {"value" :1650, "length" : 2, "type" : "num", "divide" : 1}, 
            "autoproofreadcmd"   : {"value" :1654, "length" : 2, "type" : "num", "divide" : 1} 
        } }
        self.recorddict14 = {"T06NNNNXMIN": {
            "decrypt"           : {"value" :"true"},
            "pvserial"          : {"value" :76, "length" : 10, "type" : "text", "divide" : 10},
            "date"              : {"value" :136, "divide" : 10}, 
            "group1start"       : {"value" :150, "length" : 2, "type" : "num","incl" : "no"}, 
            "group1end"         : {"value" :154, "length" : 2, "type" : "num","incl" : "no"}, 
            "pvstatus"          : {"value" : 158,"length" : 2,"type" : "num","divide" : 1},
            "pvpowerin"         : {"value" : 162,"length" : 4,"type" : "num","divide" : 10},
            "pv1voltage"        : {"value" : 170,"length" : 2,"type" : "num","divide" : 10},
            "pv1current"        : {"value" : 174,"length" : 2,"type" : "num","divide" : 10},
            "pv1watt"           : {"value" : 178,"length" : 4,"type" : "num","divide" : 10},
            "pv2voltage"        : {"value" : 186,"length" : 2,"type" : "num","divide" : 10},
            "pv2current"        : {"value" : 190,"length" : 2,"type" : "num","divide" : 10},
            "pv2watt"           : {"value" : 194,"length" : 4,"type" : "num","divide" : 10},
            "pv3voltage"        : {"value" : 202,"length" : 2,"type" : "num","divide" : 10},
            "pv3current"        : {"value" : 206,"length" : 2,"type" : "num","divide" : 10},
            "pv3watt"           : {"value" : 210,"length" : 4,"type" : "num","divide" : 10},
            "pv4voltage"        : {"value" : 218,"length" : 2,"type" : "num","divide" : 10},
            "pv4current"        : {"value" : 222,"length" : 2,"type" : "num","divide" : 10},
            "pv4watt"           : {"value" : 226,"length" : 4,"type" : "num","divide" : 10},
            "pvpowerout"        : {"value" : 250,"length" : 4,"type" : "num","divide" : 10},
            "pvfrequentie"      : {"value" : 258,"length" : 2,"type" : "num","divide" : 100},
            "pvgridvoltage"     : {"value" : 262,"length" : 2,"type" : "num","divide" : 10},
            "pvgridcurrent"     : {"value" : 266,"length" : 2,"type" : "num","divide" : 10},
            "pvgridpower"       : {"value" : 270,"length" : 4,"type" : "num","divide" : 10},
            "pvgridvoltage2"    : {"value" : 278,"length" : 2,"type" : "num","divide" : 10},
            "pvgridcurrent2"    : {"value" : 282,"length" : 2,"type" : "num","divide" : 10},
            "pvgridpower2"      : {"value" : 286,"length" : 4,"type" : "num","divide" : 10},
            "pvgridvoltage3"    : {"value" : 294,"length" : 2,"type" : "num","divide" : 10},
            "pvgridcurrent3"    : {"value" : 298,"length" : 2,"type" : "num","divide" : 10},
            "pvgridpower3"      : {"value" : 302,"length" : 4,"type" : "num","divide" : 10},
            "vacrs"            : {"value" : 310,"length" : 2,"type" : "num","divide" : 10},
            "vacst"            : {"value" : 314,"length" : 2,"type" : "num","divide" : 10},
            "vactr"            : {"value" : 318,"length" : 2,"type" : "num","divide" : 10},
            "ptousertotal"      : {"value" : 322,"length" : 4,"type" : "num","divide" : 10},
            "ptogridtotal"      : {"value" : 330,"length" : 4,"type" : "num","divide" : 10},
            "ptoloadtotal"      : {"value" : 338,"length" : 4,"type" : "num","divide" : 10},
            "totworktime"       : {"value" : 346,"length" : 4,"type" : "num","divide" : 7200},
            "pvenergytoday"     : {"value" : 354,"length" : 4,"type" : "num","divide" : 10},
            "pvenergytotal"     : {"value" : 362,"length" : 4,"type" : "num","divide" : 10},
            "epvtotal"         : {"value" : 370,"length" : 4,"type" : "num","divide" : 10},
            "epv1today"        : {"value" : 378,"length" : 4,"type" : "num","divide" : 10},
            "epv1total"         : {"value" : 386,"length" : 4,"type" : "num","divide" : 10},
            "epv2today"         : {"value" : 394,"length" : 4,"type" : "num","divide" : 10},
            "epv2total"         : {"value" : 402,"length" : 4,"type" : "num","divide" : 10},
            "epv3today"         : {"value" : 410,"length" : 4,"type" : "num","divide" : 10},
            "epv3total"         : {"value" : 418,"length" : 4,"type" : "num","divide" : 10},
            "etousertoday"      : {"value" : 426,"length" : 4,"type" : "num","divide" : 10},
            "etousertotal"      : {"value" : 434,"length" : 4,"type" : "num","divide" : 10},
            "etogridtoday"      : {"value" : 442,"length" : 4,"type" : "num","divide" : 10},
            "etogridtotal"      : {"value" : 450,"length" : 4,"type" : "num","divide" : 10},
            "eloadtoday"        : {"value" : 458,"length" : 4,"type" : "num","divide" : 10},
            "eloadtotal"        : {"value" : 466,"length" : 4,"type" : "num","divide" : 10},
            "deratingmode"      : {"value" : 502,"length" : 2,"type" : "num","divide" : 1},
            "iso"               : {"value" : 506,"length" : 2,"type" : "num","divide" : 1},
            "dcir"              : {"value" : 510,"length" : 2,"type" : "num","divide" : 10},
            "dcis"              : {"value" : 514,"length" : 2,"type" : "num","divide" : 10},
            "dcit"              : {"value" : 518,"length" : 2,"type" : "num","divide" : 10},
            "gfci"              : {"value" : 522,"length" : 4,"type" : "num","divide" : 1},
            "pvtemperature"     : {"value" : 530,"length" : 2,"type" : "num","divide" : 10},
            "pvipmtemperature"  : {"value" : 534,"length" : 2,"type" : "num","divide" : 10},
            "temp3"             : {"value" : 538,"length" : 2,"type" : "num","divide" : 10},
            "temp4"             : {"value" : 542,"length" : 2,"type" : "num","divide" : 10},
            "temp5"             : {"value" : 546,"length" : 2,"type" : "num","divide" : 10},
            "pbusvoltage"       : {"value" : 550,"length" : 2,"type" : "num","divide" : 10},
            "nbusvoltage"       : {"value" : 554,"length" : 2,"type" : "num","divide" : 10},
            "ipf"               : {"value" : 558,"length" : 2,"type" : "num","divide" : 1},
            "realoppercent"     : {"value" : 562,"length" : 2,"type" : "num","divide" : 1},
            "opfullwatt"        : {"value" : 566,"length" : 4,"type" : "num","divide" : 10},
            "standbyflag"       : {"value" : 574,"length" : 2,"type" : "num","divide" : 1},
            "faultcode"         : {"value" : 578,"length" : 2,"type" : "num","divide" : 1},
            "warningcode"       : {"value" : 582,"length" : 2,"type" : "num","divide" : 1},
            "systemfaultword0"  : {"value" : 586,"length" : 2,"type" : "num","divide" : 1},
            "systemfaultword1"  : {"value" : 590,"length" : 2,"type" : "num","divide" : 1},
            "systemfaultword2"  : {"value" : 594,"length" : 2,"type" : "num","divide" : 1},
            "systemfaultword3"  : {"value" : 598,"length" : 2,"type" : "num","divide" : 1},
            "systemfaultword4"  : {"value" : 602,"length" : 2,"type" : "num","divide" : 1},
            "systemfaultword5"  : {"value" : 606,"length" : 2,"type" : "num","divide" : 1},
            "systemfaultword6"  : {"value" : 610,"length" : 2,"type" : "num","divide" : 1},
            "systemfaultword7"  : {"value" : 614,"length" : 2,"type" : "num","divide" : 1},
            "invstartdelaytime" : {"value" : 618,"length" : 2,"type" : "num","divide" : 1},
            "bdconoffstate"     : {"value" : 630,"length" : 2,"type" : "num","divide" : 1},
            "drycontactstate"   : {"value" : 634,"length" : 2,"type" : "num","divide" : 1},
            "group2start"       : {"value" :658, "length" : 2, "type" : "num","incl" : "no"}, 
            "group2end"         : {"value" :662, "length" : 2, "type" : "num","incl" : "no"},
            "edischrtoday"      : {"value" : 666,"length" : 4,"type" : "num","divide" : 10},
            "edischrtotal"      : {"value" : 674,"length" : 4,"type" : "num","divide" : 10},
            "echrtoday"         : {"value" : 682,"length" : 4,"type" : "num","divide" : 10},
            "echrtotal"         : {"value" : 690,"length" : 4,"type" : "num","divide" : 10},
            "eacchrtoday"       : {"value" : 698,"length" : 4,"type" : "num","divide" : 10},
            "eacchrtotal"       : {"value" : 706,"length" : 4,"type" : "num","divide" : 10},
            "priority"          : {"value" : 742,"length" : 2,"type" : "num","divide" : 1},
            "epsfac"            : {"value" : 746,"length" : 2,"type" : "num","divide" : 100},
            "epsvac1"           : {"value" : 750,"length" : 2,"type" : "num","divide" : 10},
            "epsiac1"           : {"value" : 754,"length" : 2,"type" : "num","divide" : 10},
            "epspac1"           : {"value" : 758,"length" : 4,"type" : "num","divide" : 10},
            "epsvac2"           : {"value" : 766,"length" : 2,"type" : "num","divide" : 10},
            "epsiac2"           : {"value" : 770,"length" : 2,"type" : "num","divide" : 10},
            "epspac2"           : {"value" : 774,"length" : 4,"type" : "num","divide" : 10},
            "epsvac3"           : {"value" : 782,"length" : 2,"type" : "num","divide" : 10},
            "epsiac3"           : {"value" : 786,"length" : 2,"type" : "num","divide" : 10},
            "epspac3"           : {"value" : 790,"length" : 4,"type" : "num","divide" : 10},
            "epspac"            : {"value" : 798,"length" : 4,"type" : "num","divide" : 10},
            "loadpercent"       : {"value" : 806,"length" : 2,"type" : "num","divide" : 10},
            "pf"                : {"value" : 810,"length" : 2,"type" : "num","divide" : 10},
            "dcv"               : {"value" : 814,"length" : 2,"type" : "num","divide" : 1},
            "bdc1_sysstatemode" : {"value" : 830,"length" : 2,"type" : "num","divide" : 1},
            "bdc1_faultcode"    : {"value" : 834,"length" : 2,"type" : "num","divide" : 1},
            "bdc1_warncode"     : {"value" : 838,"length" : 2,"type" : "num","divide" : 1},
            "bdc1_vbat"         : {"value" : 842,"length" : 2,"type" : "num","divide" : 100},
            "bdc1_ibat"         : {"value" : 846,"length" : 2,"type" : "num","divide" : 10},
            "bdc1_soc"          : {"value" : 850,"length" : 2,"type" : "num","divide" : 1},
            "bdc1_vbus1"        : {"value" : 854,"length" : 2,"type" : "num","divide" : 10},
            "bdc1_vbus2"        : {"value" : 858,"length" : 2,"type" : "num","divide" : 10},
            "bdc1_ibb"          : {"value" : 862,"length" : 2,"type" : "num","divide" : 10},
            "bdc1_illc"         : {"value" : 866,"length" : 2,"type" : "num","divide" : 10},
            "bdc1_tempa"        : {"value" : 870,"length" : 2,"type" : "num","divide" : 10},
            "bdc1_tempb"        : {"value" : 874,"length" : 2,"type" : "num","divide" : 10},
            "bdc1_pdischr"      : {"value" : 878,"length" : 4,"type" : "num","divide" : 10},
            "bdc1_pchr"         : {"value" : 886,"length" : 4,"type" : "num","divide" : 10},
            "bdc1_edischrtotal" : {"value" : 894,"length" : 4,"type" : "num","divide" : 10},
            "bdc1_echrtotal"    : {"value" : 902,"length" : 4,"type" : "num","divide" : 10},
            "bdc1_flag"          : {"value" : 914,"length" : 2,"type" : "num","divide" : 1},
            "bdc2_sysstatemode" : {"value" : 922,"length" : 2,"type" : "num","divide" : 1},
            "bdc2_faultcode"    : {"value" : 926,"length" : 2,"type" : "num","divide" : 1},
            "bdc2_warncode"     : {"value" : 930,"length" : 2,"type" : "num","divide" : 1},
            "bdc2_vbat"         : {"value" : 934,"length" : 2,"type" : "num","divide" : 100},
            "bdc2_ibat"         : {"value" : 938,"length" : 2,"type" : "num","divide" : 10},
            "bdc2_soc"          : {"value" : 942,"length" : 2,"type" : "num","divide" : 1},
            "bdc2_vbus1"        : {"value" : 946,"length" : 2,"type" : "num","divide" : 10},
            "bdc2_vbus2"        : {"value" : 950,"length" : 2,"type" : "num","divide" : 10},
            "bdc2_ibb"          : {"value" : 954,"length" : 2,"type" : "num","divide" : 10},
            "bdc2_illc"         : {"value" : 958,"length" : 2,"type" : "num","divide" : 10},
            "bdc2_tempa"        : {"value" : 962,"length" : 2,"type" : "num","divide" : 10},
            "bdc2_tempb"        : {"value" : 966,"length" : 2,"type" : "num","divide" : 10},
            "bdc2_pdischr"      : {"value" : 970,"length" : 4,"type" : "num","divide" : 10},
            "bdc2_pchr"         : {"value" : 978,"length" : 4,"type" : "num","divide" : 10},
            "bdc2_edischrtotal" : {"value" : 986,"length" : 4,"type" : "num","divide" : 10},
            "bdc2_echrtotal"    : {"value" : 994,"length" : 4,"type" : "num","divide" : 10},
            "bdc2_flag"          : {"value" : 1006,"length" : 4,"type" : "num","divide" : 1},
            "bms_status"         : {"value" : 1014,"length" : 2,"type" : "num","divide" : 1},
            "bms_error"          : {"value" : 1018,"length" : 2,"type" : "num","divide" : 1},
            "bms_warninfo"       : {"value" : 1022,"length" : 2,"type" : "num","divide" : 1},
            "bms_soc"            : {"value" : 1026,"length" : 2,"type" : "num","divide" : 1},
            "bms_batteryvolt"    : {"value" : 1030,"length" : 2,"type" : "num","divide" : 100},
            "bms_batterycurr"    : {"value" : 1034,"length" : 2,"type" : "numx","divide" : 100},
            "bms_batterytemp"    : {"value" : 1038,"length" : 2,"type" : "num","divide" : 10},
            "bms_maxcurr"        : {"value" : 1042,"length" : 2,"type" : "num","divide" : 100},
            "bms_deltavolt"      : {"value" : 1046,"length" : 2,"type" : "num","divide" : 100},
            "bms_cyclecnt"       : {"value" : 1050,"length" : 2,"type" : "num","divide" : 1},
            "bms_soh"            : {"value" : 1054,"length" : 2,"type" : "num","divide" : 1},
            "bms_constantvolt"   : {"value" : 1058,"length" : 2,"type" : "num","divide" : 100},
            "bms_bms_info"        : {"value" : 1062,"length" : 2,"type" : "num","divide" : 1},
            "bms_packinfo"       : {"value" : 1066,"length" : 2,"type" : "num","divide" : 1},
            "bms_usingcap"       : {"value" : 1070,"length" : 2,"type" : "num","divide" : 1},
            "bms_fw"             : {"value" : 1074,"length" : 2,"type" : "num","divide" : 1},
            "bms_mcuversion"     : {"value" : 1078,"length" : 2,"type" : "num","divide" : 1},
            "bms_commtype"       : {"value" : 1082,"length" : 2,"type" : "num","divide" : 1}
	      } }
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
        self.recorddict.update(self.recorddict13)  # T06NNNNXSPA
        self.recorddict.update(self.recorddict14)  # T06NNNNXMIN
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

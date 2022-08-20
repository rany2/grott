#
# grottconf  process command parameter and settings file
# Updated: 2022-05-17
# Version 2.7.3

import argparse
import configparser
import ipaddress
import json
import os

from influxdb_client import InfluxDBClient
from influxdb_client.client.write_api import \
    SYNCHRONOUS as INFLUXDB_SYNCHRONOUS

from grottdata import pr, str2bool


class Conf:
    def __init__(self, vrm):
        self.verrel = vrm

        # Set default variables
        self.verbose = False
        self.trace = False
        self.cfgfile = "grott.ini"
        self.minrecl = 100
        self.invtype = "default"  # specify sepcial invertype default (spf, sph)
        self.includeall = False  # Include all defined keys from layout (also incl = no)
        self.blockcmd = False  # Block Inverter and Shine configure commands
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

        # Growatt server default
        self.growattip = "47.91.67.66"
        self.growattport = 5279

        # MQTT default
        self.mqttip = "localhost"
        self.mqttport = 1883
        self.mqtttopic = "energy/growatt"
        self.mqttmtopic = "False"
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

        # influxdb default
        self.influx = False
        self.ifip = "localhost"
        self.ifport = 8086
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

        # Process config file
        self.procconf()

        # Process environmental variable
        self.procenv()

        # Process environmental variable to override config and environmental settings
        self.parserset()

        # prepare MQTT security
        if not self.mqttauth:
            self.pubauth = None
        else:
            self.pubauth = dict(username=self.mqttuser, password=self.mqttpsw)

        # define recordlayouts
        self.set_reclayouts()

        # define record whitlist (if blocking / filtering enabled
        self.set_recwl()

        # prepare influxDB
        if self.influx:
            if self.verbose:
                pr("\n- Grott InfluxDB initiating started")

            self.influxclient = InfluxDBClient(
                url=f"{self.ifip}:{self.ifport}",
                org=self.iforg,
                token=self.iftoken,
            )
            self.ifbucket_api = self.influxclient.buckets_api()
            self.iforganization_api = self.influxclient.organizations_api()
            self.ifwrite_api = self.influxclient.write_api(
                write_options=INFLUXDB_SYNCHRONOUS
            )

    def print(self):
        pr("\nGrott settings:\n")
        pr("_Generic:")
        pr("\tversion:     \t", self.verrel)
        pr("\tverbose:     \t", self.verbose)
        pr("\ttrace:       \t", self.trace)
        pr("\tconfig file: \t", self.cfgfile)
        pr("\tminrecl:     \t", self.minrecl)
        pr("\tinvtype:     \t", self.invtype)
        pr("\tinclude_all: \t", self.includeall)
        pr("\tblockcmd:    \t", self.blockcmd)
        pr("\tnoipf:       \t", self.noipf)
        pr("\ttime:        \t", self.gtime)
        pr("\tsendbuf:     \t", self.sendbuf)
        pr("\ttimezone:    \t", self.tmzone)
        pr("\tinverterid:  \t", self.inverterid)
        pr("\tmode:        \t", self.mode)
        pr("\tgrottip      \t", self.grottip)
        pr("\tgrottport    \t", self.grottport)
        pr("_MQTT:")
        pr("\tnomqtt       \t", self.nomqtt)
        pr("\tmqttip:      \t", self.mqttip)
        pr("\tmqttport:    \t", self.mqttport)
        pr("\tmqtttopic:   \t", self.mqtttopic)
        pr("\tmqttmtopic:  \t", self.mqttmtopic)
        pr("\tmqttmtopicname:\t", self.mqttmtopicname)
        pr("\tmqtttretain: \t", self.mqttretain)
        pr("\tmqtttauth:   \t", self.mqttauth)
        pr("\tmqttuser:    \t", self.mqttuser)
        pr("\tmqttpsw:     \t", "**secret**")
        # print("\tmqttpsw:     \t",self.mqttpsw)
        pr("_Growatt server:")
        pr("\tgrowattip:   \t", self.growattip)
        pr("\tgrowattport: \t", self.growattport)
        pr("_PVOutput:")
        pr("\tpvoutput:    \t", self.pvoutput)
        pr("\tpvdisv1:     \t", self.pvdisv1)
        pr("\tpvtemp:      \t", self.pvtemp)
        pr("\tpvurl:       \t", self.pvurl)
        pr("\tpvapikey:    \t", self.pvapikey)
        pr("\tpvinverters: \t", self.pvinverters)
        if self.pvinverters == 1:
            pr("\tpvsystemid:  \t", self.pvsystemid[1])
        else:
            pr("\tpvsystemid:  \t", self.pvsystemid)
            pr("\tpvinvertid:  \t", self.pvinverterid)
        pr("_Influxdb:")
        pr("\tinflux:     \t", self.influx)
        pr("\tip:          \t", self.ifip)
        pr("\tport:        \t", self.ifport)
        pr("\torganization:\t", self.iforg)
        pr("\tbucket:      \t", self.ifbucket)
        pr("\ttoken:       \t", "**secret**")
        # print("\ttoken:       \t",self.iftoken)

        pr("_Extension:")
        pr("\textension:   \t", self.extension)
        pr("\textname:     \t", self.extname)
        pr("\textvar:      \t", self.extvar)

        pr()

    def parserinit(self):
        # Process commandline parameters init (read args, process c,v,o settings)
        parser = argparse.ArgumentParser(prog="grott")
        parser.add_argument("-v", "--verbose", help="set verbose", action="store_true")
        parser.add_argument("--version", action="version", version=self.verrel)
        parser.add_argument(
            "-c",
            help="set config file if not specified config file is grott.ini",
            metavar="[config file]",
        )
        parser.add_argument(
            "-o",
            help="set output file, if not specified output is stdout",
            metavar="[output file]",
        )
        parser.add_argument(
            "-m",
            help="set mode (sniff or proxy), if not specified mode is sniff",
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
            "-b",
            "--blockcmd",
            help="block Growatt configure commands",
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
        self.ablockcmd = args.blockcmd
        self.anoipf = args.noipf

        if args.m is not None:
            # print("mode: ",args.m)
            if args.m == "proxy":
                self.amode = "proxy"
            else:
                self.amode = "sniff"  # default
        if args.i is not None and args.i != "none":  # added none for docker support
            self.ainverterid = args.i

        if self.verbose:
            pr("\nGrott Command line parameters processed:")
            pr("\tverbose:     \t", self.verbose)
            pr("\tconfig file: \t", self.cfgfile)
            pr("\tnomqtt:      \t", self.anomqtt)
            pr("\tinverterid:  \t", self.inverterid)
            pr("\tpvoutput:    \t", self.apvoutput)
            pr("\tblockcmd:    \t", self.ablockcmd)
            pr("\tnoipf:       \t", self.noipf)

    def parserset(self):
        pr("\nGrott override settings if set in commandline")
        if hasattr(self, "amode"):
            self.mode = self.amode
        if hasattr(self, "ablockcmd") and self.ablockcmd:
            self.blockcmd = self.ablockcmd
        if hasattr(self, "anoipf") and self.anoipf:
            self.noipf = self.anoipf
        if hasattr(self, "ainverterid"):
            self.inverterid = self.ainverterid
        if hasattr(self, "anomqtt") and self.anomqtt:
            self.nomqtt = self.anomqtt
        if hasattr(self, "apvoutput") and self.apvoutput:
            self.pvoutput = self.apvoutput
        # Correct Bool if changed to string during parsing process
        # if self.verbose == True or self.verbose == "True" : self.verbose = True
        # else : self.verbose = False
        self.verbose = str2bool(self.verbose)
        self.trace = str2bool(self.trace)
        self.includeall = str2bool(self.includeall)
        self.blockcmd = str2bool(self.blockcmd)
        self.noipf = str2bool(self.noipf)
        self.sendbuf = str2bool(self.sendbuf)
        #
        self.nomqtt = str2bool(self.nomqtt)
        self.mqttmtopic = str2bool(self.mqttmtopic)
        self.mqttauth = str2bool(self.mqttauth)
        self.mqttretain = str2bool(self.mqttretain)
        #
        self.pvoutput = str2bool(self.pvoutput)
        self.pvdisv1 = str2bool(self.pvdisv1)
        self.pvtemp = str2bool(self.pvtemp)
        #
        self.influx = str2bool(self.influx)
        self.extension = str2bool(self.extension)

    def procconf(self):
        pr("\nGrott process configuration file")
        config = configparser.ConfigParser()
        config.read(self.cfgfile)
        if config.has_option("Generic", "minrecl"):
            self.minrecl = config.getint("Generic", "minrecl")
        if config.has_option("Generic", "verbose"):
            self.verbose = config.getboolean("Generic", "verbose")
        if config.has_option("Generic", "includeall"):
            self.includeall = config.getboolean("Generic", "includeall")
        if config.has_option("Generic", "invtype"):
            self.invtype = config.get("Generic", "invtype")
        if config.has_option("Generic", "inverterid"):
            self.inverterid = config.get("Generic", "inverterid")
        if config.has_option("Generic", "blockcmd"):
            self.blockcmd = config.get("Generic", "blockcmd")
        if config.has_option("Generic", "noipf"):
            self.noipf = config.get("Generic", "noipf")
        if config.has_option("Generic", "time"):
            self.gtime = config.get("Generic", "time")
        if config.has_option("Generic", "sendbuf"):
            self.sendbuf = config.get("Generic", "sendbuf")
        if config.has_option("Generic", "timezone"):
            self.tmzone = config.get("Generic", "timezone")
        if config.has_option("Generic", "mode"):
            self.mode = config.get("Generic", "mode")
        if config.has_option("Generic", "ip"):
            self.grottip = config.get("Generic", "ip")
        if config.has_option("Generic", "port"):
            self.grottport = config.getint("Generic", "port")
        if config.has_option("Generic", "timeout"):
            self.timeout = config.getfloat("Generic", "timeout")

        if config.has_option("Growatt", "ip"):
            self.growattip = config.get("Growatt", "ip")
        if config.has_option("Growatt", "port"):
            self.growattport = config.getint("Growatt", "port")
        if config.has_option("Server", "httpip"):
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
            self.registerwritetimeout = config.getfloat("HTTP", "registerwritetimeout")
        if config.has_option("Server", "firstping"):
            self.firstping = config.getboolean("Server", "firstping")
        if config.has_option("Server", "sendseq"):
            self.sendseq = config.getint("Server", "sendseq")
        if config.has_option("Server", "serverforward"):
            self.serverforward = config.getboolean("Server", "serverforward")
        if config.has_option("Server", "forwardretry"):
            self.forwardretry = config.getint("Server", "forwardretry")
        if config.has_option("Server", "forwardtimeout"):
            self.forwardtimeout = config.getfloat("Server", "forwardtimeout")
        if config.has_option("MQTT", "nomqtt"):
            self.nomqtt = config.get("MQTT", "nomqtt")
        if config.has_option("MQTT", "ip"):
            self.mqttip = config.get("MQTT", "ip")
        if config.has_option("MQTT", "port"):
            self.mqttport = config.getint("MQTT", "port")
        if config.has_option("MQTT", "topic"):
            self.mqtttopic = config.get("MQTT", "topic")
        if config.has_option("MQTT", "mtopic"):
            self.mqttmtopic = config.get("MQTT", "mtopic")
        if config.has_option("MQTT", "mtopicname"):
            self.mqttmtopicname = config.get("MQTT", "mtopicname")
        if config.has_option("MQTT", "retain"):
            self.mqttretain = config.getboolean("MQTT", "retain")
        if config.has_option("MQTT", "auth"):
            self.mqttauth = config.getboolean("MQTT", "auth")
        if config.has_option("MQTT", "user"):
            self.mqttuser = config.get("MQTT", "user")
        if config.has_option("MQTT", "password"):
            self.mqttpsw = config.get("MQTT", "password")
        if config.has_option("PVOutput", "pvoutput"):
            self.pvoutput = config.get("PVOutput", "pvoutput")
        if config.has_option("PVOutput", "pvtemp"):
            self.pvtemp = config.get("PVOutput", "pvtemp")
        if config.has_option("PVOutput", "pvdisv1"):
            self.pvdisv1 = config.get("PVOutput", "pvdisv1")
        if config.has_option("PVOutput", "pvinverters"):
            self.pvinverters = config.getint("PVOutput", "pvinverters")
        if config.has_option("PVOutput", "apikey"):
            self.pvapikey = config.get("PVOutput", "apikey")
        # if more inverter are installed at the same interface (shinelink) get systemids
        # if self.pvinverters > 1 :
        for x in range(self.pvinverters + 1):
            if config.has_option("PVOutput", "systemid" + str(x)):
                self.pvsystemid[x] = config.get("PVOutput", "systemid" + str(x))
            if config.has_option("PVOutput", "inverterid" + str(x)):
                self.pvinverterid[x] = config.get("PVOutput", "inverterid" + str(x))
        if self.pvinverters == 1:
            if config.has_option("PVOutput", "systemid"):
                self.pvsystemid[1] = config.get("PVOutput", "systemid")
        # INFLUX
        if config.has_option("influx", "influx"):
            self.influx = config.get("influx", "influx")
        if config.has_option("influx", "ip"):
            self.ifip = config.get("influx", "ip")
        if config.has_option("influx", "port"):
            self.ifport = int(config.get("influx", "port"))
        if config.has_option("influx", "org"):
            self.iforg = config.get("influx", "org")
        if config.has_option("influx", "bucket"):
            self.ifbucket = config.get("influx", "bucket")
        if config.has_option("influx", "token"):
            self.iftoken = config.get("influx", "token")
        # extension
        if config.has_option("extension", "extension"):
            self.extension = config.get("extension", "extension")
        if config.has_option("extension", "extname"):
            self.extname = config.get("extension", "extname")
        if config.has_option("extension", "extvar"):
            self.extvar = eval(config.get("extension", "extvar"))

    def getenv(self, envvar):
        envval = os.getenv(envvar)

        if self.verbose:
            pr(f"\n\tPulled '{envvar}={envval}' from the environment")
        return envval

    def procenv(self):
        pr("\nGrott process environmental variables")
        if os.getenv("gmode") in ("sniff", "proxy"):
            self.mode = self.getenv("gmode")
        if os.getenv("gverbose") is not None:
            self.verbose = self.getenv("gverbose")
        if os.getenv("gminrecl") is not None:
            if 0 <= int(os.getenv("gminrecl")) <= 255:
                self.minrecl = int(self.getenv("gminrecl"))
        if os.getenv("gincludeall") is not None:
            self.includeall = self.getenv("gincludeall")
        if os.getenv("ginvtype") is not None:
            self.invtype = self.getenv("ginvtype")
        if os.getenv("gblockcmd") is not None:
            self.blockcmd = self.getenv("gblockcmd")
        if os.getenv("gnoipf") is not None:
            self.noipf = self.getenv("gnoipf")
        if os.getenv("gtime") in ("auto", "server"):
            self.gtime = self.getenv("gtime")
        if os.getenv("gtimezone") is not None:
            self.tmzone = self.getenv("gtimezone")
        if os.getenv("gsendbuf") is not None:
            self.sendbuf = self.getenv("gsendbuf")
        if os.getenv("ginverterid") is not None:
            self.inverterid = self.getenv("ginverterid")
        if os.getenv("ggrottip") is not None:
            try:
                ipaddress.ip_address(os.getenv("ggrottip"))
                self.grottip = self.getenv("ggrottip")
            except ValueError:
                if self.verbose:
                    pr("\nGrott IP address env invalid")
        if os.getenv("ggrottport") is not None:
            if 0 <= int(os.getenv("ggrottport")) <= 65535:
                self.grottport = self.getenv("ggrottport")
        if os.getenv("ggrowattip") is not None:
            try:
                ipaddress.ip_address(os.getenv("ggrowattip"))
                self.growattip = self.getenv("ggrowattip")
            except ValueError:
                if self.verbose:
                    pr("\nGrott Growatt server IP address env invalid")
        if os.getenv("ggrowattport") is not None:
            if 0 <= int(os.getenv("ggrowattport")) <= 65535:
                self.growattport = int(self.getenv("ggrowattport"))
            else:
                if self.verbose:
                    pr("\nGrott Growatt server Port address env invalid")
        # handle mqtt environmentals
        if os.getenv("gnomqtt") is not None:
            self.nomqtt = self.getenv("gnomqtt")
        if os.getenv("gmqttip") is not None:
            try:
                ipaddress.ip_address(os.getenv("gmqttip"))
                self.mqttip = self.getenv("gmqttip")
            except ValueError:
                if self.verbose:
                    pr("\nGrott MQTT server IP address env invalid")
        if os.getenv("gmqttport") is not None:
            if 0 <= int(os.getenv("gmqttport")) <= 65535:
                self.mqttport = int(self.getenv("gmqttport"))
            else:
                if self.verbose:
                    pr("\nGrott MQTT server Port address env invalid")

        if os.getenv("gmqtttopic") is not None:
            self.mqtttopic = self.getenv("gmqtttopic")
        if os.getenv("gmqttmtopic") is not None:
            self.mqttmtopic = self.getenv("gmqttmtopic")
        if os.getenv("gmqttmtopicname") is not None:
            self.mqttmtopicname = self.getenv("gmqttmtopicname")
        if os.getenv("gmqttretain") is not None:
            self.mqttretain = self.getenv("gmqttretain")
        if os.getenv("gmqttauth") is not None:
            self.mqttauth = self.getenv("gmqttauth")
        if os.getenv("gmqttuser") is not None:
            self.mqttuser = self.getenv("gmqttuser")
        if os.getenv("gmqttpassword") is not None:
            self.mqttpsw = self.getenv("gmqttpassword")
        # Handle PVOutput variables
        if os.getenv("gpvoutput") is not None:
            self.pvoutput = self.getenv("gpvoutput")
        if os.getenv("gpvtemp") is not None:
            self.pvtemp = self.getenv("gpvtemp")
        if os.getenv("gpvdisv1") is not None:
            self.pvdisv1 = self.getenv("gpvdisv1")
        if os.getenv("gpvapikey") is not None:
            self.pvapikey = self.getenv("gpvapikey")
        if os.getenv("gpvinverters") is not None:
            self.pvinverters = int(self.getenv("gpvinverters"))
        for x in range(self.pvinverters + 1):
            if os.getenv("gpvsystemid" + str(x)) is not None:
                self.pvsystemid[x] = self.getenv("gpvsystemid" + str(x))
            if os.getenv("gpvinverterid" + str(x)) is not None:
                self.pvinverterid[x] = self.getenv("gpvinverterid" + str(x))
        if self.pvinverters == 1:
            if os.getenv("gpvsystemid") is not None:
                self.pvsystemid[1] = self.getenv("gpvsystemid")
        # Handle Influx
        if os.getenv("ginflux") is not None:
            self.influx = self.getenv("ginflux")
        if os.getenv("gifip") is not None:
            try:
                ipaddress.ip_address(os.getenv("gifip"))
                self.ifip = self.getenv("gifip")
            except ValueError:
                if self.verbose:
                    pr("\nGrott InfluxDB server IP address env invalid")
        if os.getenv("gifport") is not None:
            if 0 <= int(os.getenv("gifport")) <= 65535:
                self.ifport = int(self.getenv("gifport"))
            else:
                if self.verbose:
                    pr("\nGrott InfluxDB server Port address env invalid")
        if os.getenv("giforg") is not None:
            self.iforg = self.getenv("giforg")
        if os.getenv("gifbucket") is not None:
            self.ifbucket = self.getenv("gifbucket")
        if os.getenv("giftoken") is not None:
            self.iftoken = self.getenv("giftoken")
        # Handle Extension
        if os.getenv("gextension") is not None:
            self.extension = self.getenv("gextension")
        if os.getenv("gextname") is not None:
            self.extname = self.getenv("gextname")
        if os.getenv("gextvar") is not None:
            self.extvar = eval(self.getenv("gextvar"))

    def set_recwl(self):
        # define record that will not be blocked or inspected if blockcmd is specified
        self.recwl = {
            "0103",  # announce record
            "0104",  # data record
            "0116",  # ping
            "0105",  # identify/display inverter config
            "0119",  # identify/display datalogger config
            "0120",  # Smart Monitor Record
            "0150",  # Archived record
            "5003",  # announce record
            "5004",  # data record
            "5016",  # ping
            "5005",  # identify/display inverter config
            "5019",  # identify/display datalogger config
            "501b",  # SDM630 with Raillog
            "5050",  # Archived record
            "5103",  # announce record
            "5104",  # data record
            "5116",  # ping
            "5105",  # identify/display inverter config
            "5119",  # identify/display datalogger config
            "5129",  # announce record
            "5150",  # Archived record
            "5216",  # ping
            "5219",  # identify/display datalogger config
            "5229",  # announce record
            "5250",  # Archived record
        }

        try:
            with open("recwl.txt", "r", encoding="utf-8") as f:
                self.recwl = f.read().splitlines()
            if self.verbose:
                pr("\nGrott external record whitelist: 'recwl.txt' read")
        except FileNotFoundError:
            if self.verbose:
                pr("\nGrott external record whitelist 'recwl.txt' not found")
        if self.verbose:
            pr("\nGrott records whitelisted : ", self.recwl)

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
            if x[0].lower() == "t" and x.find(".json") > 0:
                pr(x)
                with open(x, "r", encoding="utf-8") as json_file:
                    dicttemp = json.load(json_file)
                    self.recorddict.update(dicttemp)

        if self.verbose:
            pr("\nGrott layout records loaded")
        for key, value in self.recorddict.items():
            if self.verbose:
                pr(key, " : ")
            if self.verbose:
                pr(value)

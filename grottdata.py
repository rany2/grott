# grottdata.py processing data  functions
# Version 2.7.5
# Updated: 2022-07-30

import codecs
import importlib
import json
import sys
import textwrap
import time
import traceback
from copy import deepcopy
from datetime import datetime, timezone
from itertools import cycle

import pytz
import requests
from paho.mqtt import publish


def pr(*args, **kwargs):
    kwargs.setdefault("flush", True)
    kwargs.setdefault("file", sys.stderr)
    return print(*args, **kwargs)


# Formats multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = "".join(rf"\x{byte:02x}" for byte in string)
        if size % 2:
            size -= 1
    return "\n".join([prefix + line for line in textwrap.wrap(string, size)])


# decrypt data.
def decrypt(decdata):

    ndecdata = len(decdata)

    # Create mask and convert to hexadecimal
    mask = "Growatt"
    hex_mask = [f"{ord(x):02x}" for x in mask]
    nmask = len(hex_mask)

    # start decrypt routine
    unscrambled = list(decdata[0:8])  # take unscramble header

    for i, j in zip(range(0, ndecdata - 8), cycle(range(0, nmask))):
        unscrambled = unscrambled + [decdata[i + 8] ^ int(hex_mask[j], 16)]

    result_string = "".join(f"{n:02x}" for n in unscrambled)

    return result_string


def str2bool(defstr):
    if defstr in ("True", "true", "TRUE", "y", "Y", "yes", "YES", 1, "1"):
        defret = True
    if defstr in ("False", "false", "FALSE", "n", "N", "no", "NO", 0, "0"):
        defret = False
    if "defret" in locals():
        return defret
    return ()


def procdata(conf, data):
    if conf.verbose:
        pr("- Growatt original Data:\n" + format_multi_line("\t ", data))

    header = "".join(f"{n:02x}" for n in data[0:8])
    ndata = len(data)
    buffered = "nodetect"  # set buffer detection to nodetect (for compat mode), wil in auto detection changed to no or yes

    # automatic detect protocol (decryption and protocol) only if compat = False!
    novalidrec = False
    if conf.verbose:
        pr("- Grott automatic protocol detection")
        pr("- Grott data record length", ndata)
    layout = "T" + header[6:8] + header[12:14] + header[14:16]
    # v270 add X for extended except for smart monitor records
    if (ndata > 375) and (header[14:16] not in ("20", "1b")):
        layout = layout + "X"

    # v270 no invtype added to layout for smart monitor records
    if (conf.invtype != "default") and (header[14:16] not in ("20", "1b")):
        layout = layout + conf.invtype.upper()

    if header[14:16] == "50":
        buffered = "yes"
    else:
        buffered = "no"

    if conf.verbose:
        pr("- layout   : ", layout)
    try:
        # does record layout record exists?
        _ = conf.recorddict[layout]
    except KeyError:
        # try generic if generic record exist
        if conf.verbose:
            pr("- no matching record layout found, try generic")
        if header[14:16] in ("04", "50"):
            layout = layout.replace(header[12:16], "NNNN")
            try:
                # does generic record layout record exists?
                _ = conf.recorddict[layout]
            except KeyError:
                # no valid record fall back on old processing?
                if conf.verbose:
                    pr(
                        "- no matching record layout found, standard processing performed"
                    )
                layout = "none"
                novalidrec = True
        else:
            novalidrec = True

    if conf.verbose:
        pr("- Record layout used:", layout)

    # Decrypt
    try:
        # see if decrypt keyword is defined
        decrypt_needed = str2bool(conf.recorddict[layout]["decrypt"]["value"])
    except KeyError:
        # if decrypt not defined, default is decrypt
        decrypt_needed = True

    if decrypt_needed:
        result_string = decrypt(data)
        if conf.verbose:
            pr("- Grott Growatt data decrypted")
    else:
        # do not decrypt
        result_string = data.hex()
        if conf.verbose:
            pr("- Grott Growatt unencrypted data used")

    if conf.verbose:
        pr("- Growatt plain data:\n" + format_multi_line("\t", result_string))
        # debug only: print(result_string)

    # test position :
    # print(result_string.find('0074' ))

    # Test length if < 12 it is a data ack record, if novalidrec flag is true it is not a (recognized) data record
    if ndata < 12 or novalidrec:
        if conf.verbose:
            pr("- Grott data ack record or data record not defined no processing done")
        return

    # Inital flag to detect off real data is processed
    dataprocessed = False

    # define dictonary for key values.
    definedkey = {}

    # layout processing
    if conf.verbose:
        pr(
            "- Growatt layout processing\n"
            f"\t - decrypt       : {decrypt_needed}\n"
            f"\t - record layout : {layout}\n"
        )

    try:
        # v270 try if logstart and log fields are defined, if yes prepare log fields
        _ = conf.recorddict[layout]["logstart"]["value"]
        logdict = (
            bytes.fromhex(
                result_string[
                    conf.recorddict[layout]["logstart"]["value"] : len(result_string)
                    - 4
                ]
            )
            .decode("ASCII")
            .split(",")
        )
    except Exception:
        pass

    # v270 log data record processing (SDM630 smart monitor with railog
    # if rectype == "data" :
    for keyword in conf.recorddict[layout].keys():

        if keyword not in ("decrypt", "date", "logstart", "device"):
            # try if keyword should be included
            include = True
            try:
                # try if key type is specified
                if conf.recorddict[layout][keyword]["incl"] == "no":
                    include = False
            except KeyError:
                pass

            # process only keyword needs to be included (default):
            try:
                if include or conf.includeall:
                    try:
                        # try if key type is specified
                        keytype = conf.recorddict[layout][keyword]["type"]
                    except KeyError:
                        # if not default is num
                        keytype = "num"
                    if keytype == "text":
                        definedkey[keyword] = result_string[
                            conf.recorddict[layout][keyword]["value"] : conf.recorddict[
                                layout
                            ][keyword]["value"]
                            + (conf.recorddict[layout][keyword]["length"] * 2)
                        ]
                        definedkey[keyword] = codecs.decode(
                            definedkey[keyword], "hex"
                        ).decode("utf-8")
                        # print(definedkey[keyword])
                    if keytype == "num":
                        # else:
                        definedkey[keyword] = int(
                            result_string[
                                conf.recorddict[layout][keyword][
                                    "value"
                                ] : conf.recorddict[layout][keyword]["value"]
                                + (conf.recorddict[layout][keyword]["length"] * 2)
                            ],
                            16,
                        )
                    if keytype == "numx":
                        # process signed integer
                        keybytes = bytes.fromhex(
                            result_string[
                                conf.recorddict[layout][keyword][
                                    "value"
                                ] : conf.recorddict[layout][keyword]["value"]
                                + (conf.recorddict[layout][keyword]["length"] * 2)
                            ]
                        )
                        definedkey[keyword] = int.from_bytes(
                            keybytes, byteorder="big", signed=True
                        )
                    if keytype == "log":
                        # Proces log fields
                        definedkey[keyword] = logdict[
                            conf.recorddict[layout][keyword]["pos"] - 1
                        ]
                    if keytype == "logpos":
                        # only display this field if positive
                        # Proces log fields
                        if (
                            float(logdict[conf.recorddict[layout][keyword]["pos"] - 1])
                            > 0
                        ):
                            definedkey[keyword] = logdict[
                                conf.recorddict[layout][keyword]["pos"] - 1
                            ]
                        else:
                            definedkey[keyword] = 0
                    if keytype == "logneg":
                        # only display this field if negative
                        # Proces log fields
                        if (
                            float(logdict[conf.recorddict[layout][keyword]["pos"] - 1])
                            < 0
                        ):
                            definedkey[keyword] = logdict[
                                conf.recorddict[layout][keyword]["pos"] - 1
                            ]
                        else:
                            definedkey[keyword] = 0
            except Exception:
                if conf.verbose:
                    pr(
                        "- grottdata - error in keyword processing:",
                        keyword + ", data processing stopped",
                    )
                return

    # test if pvserial was defined, if not take inverterid from config.
    device_defined = False
    try:
        definedkey["device"] = conf.recorddict[layout]["device"]["value"]
        device_defined = True
    except KeyError:
        # test if pvserial was defined, if not take inverterid from config.
        try:
            _ = definedkey["pvserial"]
        except KeyError:
            definedkey["pvserial"] = conf.inverterid
            conf.recorddict[layout]["pvserial"] = {"value": 0, "type": "text"}
            if conf.verbose:
                pr(
                    "- pvserial not found and device not specified used config defined invertid:",
                    definedkey["pvserial"],
                )

    # test if dateoffset is defined, if not take set to 0 (no futher date retrieval processing) .
    try:
        # test of date is specified in layout
        dateoffset = int(conf.recorddict[layout]["date"]["value"])
    except (ValueError, KeyError, TypeError):
        # no date specified, default no date specified
        dateoffset = 0

    # proces date value if specifed
    if dateoffset > 0 and (conf.gtime != "server" or buffered == "yes"):
        if conf.verbose:
            pr("- Grott data record date/time processing started")
        # date
        pvyearI = int(result_string[dateoffset : dateoffset + 2], 16)
        if pvyearI < 10:
            pvyear = "200" + str(pvyearI)
        else:
            pvyear = "20" + str(pvyearI)
        pvmonthI = int(result_string[dateoffset + 2 : dateoffset + 4], 16)
        if pvmonthI < 10:
            pvmonth = "0" + str(pvmonthI)
        else:
            pvmonth = str(pvmonthI)
        pvdayI = int(result_string[dateoffset + 4 : dateoffset + 6], 16)
        if pvdayI < 10:
            pvday = "0" + str(pvdayI)
        else:
            pvday = str(pvdayI)
        # Time
        pvhourI = int(result_string[dateoffset + 6 : dateoffset + 8], 16)
        if pvhourI < 10:
            pvhour = "0" + str(pvhourI)
        else:
            pvhour = str(pvhourI)
        pvminuteI = int(result_string[dateoffset + 8 : dateoffset + 10], 16)
        if pvminuteI < 10:
            pvminute = "0" + str(pvminuteI)
        else:
            pvminute = str(pvminuteI)
        pvsecondI = int(result_string[dateoffset + 10 : dateoffset + 12], 16)
        if pvsecondI < 10:
            pvsecond = "0" + str(pvsecondI)
        else:
            pvsecond = str(pvsecondI)
        # create date/time is format
        pvdate = f"{pvyear}-{pvmonth}-{pvday}T{pvhour}:{pvminute}:{pvsecond}"
        # test if valid date/time in data record
        try:
            _ = datetime.strptime(pvdate, "%Y-%m-%dT%H:%M:%S")
            jsondate = pvdate
            if conf.verbose:
                pr("\t - date-time: ", jsondate)
            timefromserver = (
                False  # Indicate of date/time is from server (used for buffered data)
            )
        except ValueError:
            # Date could not be parsed - either the format is different or it's not a
            # valid date
            if conf.verbose:
                pr(
                    "\t - no or no valid time/date found, grott server time will be used (buffer records not sent!)"
                )
            timefromserver = True
            jsondate = datetime.now().replace(microsecond=0).isoformat()
    else:
        if conf.verbose:
            pr("- Grott server date/time used")
        jsondate = datetime.now().replace(microsecond=0).isoformat()
        timefromserver = True

    dataprocessed = True

    if dataprocessed:
        # only sendout data to MQTT if it is processed.

        # Print values
        if conf.verbose:
            pr("- Grott values retrieved:")
            for key, value in definedkey.items():
                # test if there is an divide factor is specifed
                try:
                    keydivide = conf.recorddict[layout][key]["divide"]
                except KeyError:
                    keydivide = 1

                if not isinstance(value, str) and keydivide != 1:
                    printkey = f"{value / keydivide:.1f}"
                else:
                    printkey = value
                pr("\t - ", key.ljust(20) + " : ", printkey)

        # create JSON message  (first create obj dict and then convert to a JSON message)

        # filter invalid 0120 record (0 < voltage_l1 > 500 )
        if header[14:16] == "20":
            if 0 < definedkey["voltage_l1"] / 10 > 500:
                pr("- Grott invalid 0120 record processing stopped")
                return

        # v270
        # compatibility with prev releases for "20" smart monitor record!
        # if device is not specified in layout record datalogserial is used
        # as device (to distinguish record from inverter record)

        if device_defined:
            jsonobj = {
                "device": definedkey["device"],
                "time": jsondate,
                "buffered": buffered,
                "values": {},
            }
        else:

            if header[14:16] not in ("20", "1b"):
                jsonobj = {
                    "device": definedkey["pvserial"],
                    "time": jsondate,
                    "buffered": buffered,
                    "values": {},
                }
            else:
                jsonobj = {
                    "device": definedkey["datalogserial"],
                    "time": jsondate,
                    "buffered": buffered,
                    "values": {},
                }

        for key, value in definedkey.items():
            jsonobj["values"][key] = value

        jsonmsg = json.dumps(jsonobj)

        if conf.verbose:
            pr("- MQTT jsonmsg:\n" + format_multi_line("\t", jsonmsg))

        # do not process invalid records (e.g. buffered records with time from server) or buffered records if sendbuf = False
        if buffered == "yes":
            if not conf.sendbuf or timefromserver:
                if conf.verbose:
                    pr(
                        "- Buffered record not sent: sendbuf = False or invalid date/time format"
                    )
                return

        if not conf.nomqtt:
            # if meter data use mqtttopicname topic
            if (header[14:16] in ("20", "1b")) and conf.mqttmtopic:
                mqtttopic = conf.mqttmtopicname
            else:
                mqtttopic = conf.mqtttopic
            pr("- Grott MQTT topic used: " + mqtttopic)

            if conf.mqttretain:
                if conf.verbose:
                    pr("- Grott MQTT message retain enabled")

            try:
                # v2.7.1 add retrain variable
                publish.single(
                    mqtttopic,
                    payload=jsonmsg,
                    qos=0,
                    retain=conf.mqttretain,
                    hostname=conf.mqttip,
                    port=conf.mqttport,
                    client_id=conf.inverterid,
                    keepalive=60,
                    auth=conf.pubauth,
                )
                if conf.verbose:
                    pr("- MQTT message message sent")
            except TimeoutError:
                if conf.verbose:
                    pr("- MQTT connection time out error")
            except ConnectionRefusedError:
                if conf.verbose:
                    pr("- MQTT connection refused by target")
            except BaseException as error:
                if conf.verbose:
                    pr("- MQTT send failed:", str(error))
        else:
            if conf.verbose:
                pr("- No MQTT message sent, MQTT disabled")

        # process pvoutput if enabled
        if conf.pvoutput:
            pvidfound = False
            if conf.pvinverters == 1:
                pvssid = conf.pvsystemid[1]
                pvidfound = True
            else:
                for pvnum, pvid in conf.pvinverterid.items():
                    if pvid == definedkey["pvserial"]:
                        pvssid = conf.pvsystemid[pvnum]
                        pvidfound = True

            if not pvidfound:
                if conf.verbose:
                    pr(
                        "- pvsystemid not found for inverter : ",
                        definedkey["pvserial"],
                    )
                return
            if conf.verbose:
                pr(
                    "- Grott send data to PVOutput systemid: ",
                    pvssid,
                    "for inverter: ",
                    definedkey["pvserial"],
                )
            pvheader = {
                "X-Pvoutput-Apikey": conf.pvapikey,
                "X-Pvoutput-SystemId": pvssid,
            }

            pvodate = jsondate[:4] + jsondate[5:7] + jsondate[8:10]
            # debug: pvodate = jsondate[:4] +jsondate[5:7] + "16"
            pvotime = jsondate[11:16]
            # debug: pvotime = "09:05"
            # if record is a smart monitor record sent smart monitor data to PVOutput
            if header[14:16] != "20":
                pvdata = {
                    "d": pvodate,
                    "t": pvotime,
                    # 2.7.1    "v1"    : definedkey["pvenergytoday"]*100,
                    "v2": definedkey["pvpowerout"] / 10,
                    "v6": definedkey["pvgridvoltage"] / 10,
                }
                if not conf.pvdisv1:
                    pvdata["v1"] = definedkey["pvenergytoday"] * 100
                else:
                    if conf.verbose:
                        pr("- Grott PVOutput send V1 disabled")

                if conf.pvtemp:
                    pvdata["v5"] = definedkey["pvtemperature"] / 10

                if conf.verbose:
                    pr("- ", pvheader)
                    pr("- ", pvdata)
                reqret = requests.post(conf.pvurl, data=pvdata, headers=pvheader)
                if conf.verbose:
                    pr("- Grott PVOutput response:")
                    pr("\t - ", reqret.text)
            else:
                # send smat monitor data c1 = 3 indiates v3 is lifetime energy
                # (day will be calculated), n=1 indicates is net data (import / export)
                # value seprated because it is not allowed to sent combination at once
                pvdata1 = {
                    "d": pvodate,
                    "t": pvotime,
                    "v3": definedkey["pos_act_energy"] * 100,
                    "c1": 3,
                    "v6": definedkey["voltage_l1"] / 10,
                }

                pvdata2 = {
                    "d": pvodate,
                    "t": pvotime,
                    "v4": definedkey["pos_rev_act_power"] / 10,
                    "v6": definedkey["voltage_l1"] / 10,
                    "n": 1,
                }
                # "v4"    : definedkey["pos_act_power"]/10,
                if conf.verbose:
                    pr("\t - ", pvheader)
                    pr("\t - ", pvdata1)
                    pr("\t - ", pvdata2)
                reqret = requests.post(conf.pvurl, data=pvdata1, headers=pvheader)
                if conf.verbose:
                    pr("- Grott PVOutput response SM1:\n" + "\t - ", reqret.text)
                reqret = requests.post(conf.pvurl, data=pvdata2, headers=pvheader)
                if conf.verbose:
                    pr("- Grott PVOutput response SM2:\n" + "\t - ", reqret.text)
        else:
            if conf.verbose:
                pr("- Grott Send data to PVOutput disabled ")

    # influxDB processing
    if conf.influx:
        if conf.verbose:
            pr("- Grott InfluxDB publihing started")
        try:
            local = pytz.timezone(conf.tmzone)
        except pytz.UnknownTimeZoneError:
            if conf.verbose:
                if conf.tmzone == "local":
                    pr("- Timezone local specified default timezone used")
                else:
                    pr(
                        "- Grott unknown timezone : ",
                        conf.tmzone,
                        ", default timezone used",
                    )
            conf.tmzone = "local"
            local = int(time.timezone / 3600)

        if conf.tmzone == "local":
            curtz = (
                datetime.now(timezone.utc)
                .astimezone()
                .tzinfo.utcoffset(datetime.strptime(jsondate, "%Y-%m-%dT%H:%M:%S"))
            )
            utc_dt = datetime.strptime(jsondate, "%Y-%m-%dT%H:%M:%S") - curtz
        else:
            naive = datetime.strptime(jsondate, "%Y-%m-%dT%H:%M:%S")
            local_dt = local.localize(naive, is_dst=None)
            utc_dt = local_dt.astimezone(pytz.utc)

        ifdt = utc_dt.strftime("%Y-%m-%dT%H:%M:%S")
        if conf.verbose:
            pr(
                "- Grott original time : ",
                jsondate,
                "adjusted UTC time for influx : ",
                ifdt,
            )

        # prepare influx jsonmsg dictionary

        # if record is a smart monitor record use datalogserial as measurement (to distinguish from solar record)
        if header[14:16] != "20":
            ifobj = {"measurement": definedkey["pvserial"], "time": ifdt, "fields": {}}
        else:
            ifobj = {
                "measurement": definedkey["datalogserial"],
                "time": ifdt,
                "fields": {},
            }

        for key, value in definedkey.items():
            if key != "date":
                ifobj["fields"][key] = value

        # Create list for influx
        ifjson = [ifobj]

        if conf.verbose:
            pr("- Grott influxdb jsonmsg:\n" + format_multi_line("\t", str(ifjson)))

        try:
            if conf.influx2:
                if conf.verbose:
                    pr("- Grott write to influxdb v2")
                _ = conf.ifwrite_api.write(conf.ifbucket, conf.iforg, ifjson)
            else:
                if conf.verbose:
                    pr("- Grott write to influxdb v1")
                _ = conf.influxclient.write_points(ifjson)
        except Exception as e:
            pr("- Grott InfluxDB error:", e)
            raise SystemExit("Grott Influxdb write error, grott will be stopped") from e

    else:
        if conf.verbose:
            pr("- Grott Send data to Influx disabled ")

    if conf.extension:

        if conf.verbose:
            pr("- Grott extension processing started: ", conf.extname)

        try:
            module = importlib.import_module(conf.extname, package=None)
        except Exception:
            if conf.verbose:
                pr("- Grott import extension failed:", conf.extname)
            return

        try:
            grottext_conf = deepcopy(conf)
            grottext_conf["layout"] = layout
            ext_result = module.grottext(conf, result_string, jsonmsg)
            if conf.verbose:
                pr("- Grott extension processing ended: ", ext_result)
        except Exception as e:
            pr("- Grott extension processing error:", repr(e))
            traceback.format_exc()
    else:
        if conf.verbose:
            pr("- Grott extension processing disabled ")

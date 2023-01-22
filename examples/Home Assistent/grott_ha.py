# coding=utf-8
# author Etienne G.

import json
from datetime import datetime, timezone

from paho.mqtt.publish import single, multiple

from grottconf import Conf
from grottdata import pr

__version__ = "0.0.5"

"""A pluging for grott
This plugin allow to have autodiscovery of the device in HA

Should be able to support multiples inverters

Config:
    - ha_mqtt_host (required): The host of the MQTT broker user by HA (often the IP of HA)
    - ha_mqtt_port (required): The port (the default is oftent 1883)
    - ha_mqtt_user (optional): The user use to connect to the broker (you can use your user)
    - ha_mqtt_password (optional): The password to connect to the mqtt broket (you can use your password)

Return codes:
    - 0: Everything is OK
    - 1: Missing MQTT extvar configuration
    - 2: Error while publishing the measure value message
    - 3: MQTT connection error
    - 4: Error while creating last_push status key
    - 5: Refused to push a buffered message (prevent invalid stats, not en error)
    - 6: Error while configuring HA MQTT sensor devices
    - 7: Can't configure device for HA MQTT
"""


config_topic = "homeassistant/{sensor_type}/grott/{device}_{attribut}/config"
state_topic = "homeassistant/grott/{device}/state"


mapping = {
    "datalogserial": {
        "name": "Datalogger serial",
    },
    "pvserial": {"name": "Serial"},
    "pv1watt": {
        "state_class": "measurement",
        "device_class": "power",
        "name": "PV1 Watt",
        "unit_of_measurement": "w",
        "value_template": "{{value_json.pv1watt| float / 10 }}",
    },
    "pv1voltage": {
        "state_class": "measurement",
        "device_class": "voltage",
        "name": "PV1 Voltage",
        "unit_of_measurement": "V",
        "value_template": "{{value_json.pv1voltage| float / 10 }}",
    },
    "pv1current": {
        "state_class": "measurement",
        "device_class": "current",
        "name": "PV1 Current",
        "unit_of_measurement": "A",
        "value_template": "{{value_json.pv1current| float / 10 }}",
    },
    "pv2watt": {
        "state_class": "measurement",
        "device_class": "power",
        "name": "PV2 Watt",
        "unit_of_measurement": "w",
        "value_template": "{{value_json.pv2watt| float / 10 }}",
    },
    "pv2voltage": {
        "state_class": "measurement",
        "device_class": "voltage",
        "name": "PV2 Voltage",
        "unit_of_measurement": "V",
        "value_template": "{{value_json.pv2voltage| float / 10 }}",
    },
    "pv2current": {
        "state_class": "measurement",
        "device_class": "current",
        "name": "PV2 Current",
        "unit_of_measurement": "A",
        "value_template": "{{value_json.pv2current| float / 10 }}",
    },
    "pvpowerin": {
        "state_class": "measurement",
        "device_class": "power",
        "name": "Input kiloWatt (Actual)",
        "unit_of_measurement": "kW",
        "value_template": "{{value_json.pvpowerin| float / 10000 }}",
    },
    "pvpowerout": {
        "state_class": "measurement",
        "device_class": "power",
        "name": "Output kiloWatt (Actual)",
        "unit_of_measurement": "kW",
        "value_template": "{{value_json.pvpowerout| float / 10000 }}",
    },
    "pvfrequentie": {
        "state_class": "measurement",
        "device_class": "frequency",
        "name": "Grid frequency",
        "unit_of_measurement": "Hz",
        "value_template": "{{value_json.pvfrequentie| float / 100 }}",
        "icon": "mdi:waveform",
    },
    # Grid config
    "pvgridvoltage": {
        "state_class": "measurement",
        "device_class": "voltage",
        "name": "Phase 1 voltage",
        "unit_of_measurement": "V",
        "value_template": "{{value_json.pvgridvoltage| float / 10 }}",
    },
    "pvgridvoltage2": {
        "state_class": "measurement",
        "device_class": "voltage",
        "name": "Phase 2 voltage",
        "unit_of_measurement": "V",
        "value_template": "{{value_json.pvgridvoltage2| float / 10 }}",
    },
    "pvgridvoltage3": {
        "state_class": "measurement",
        "device_class": "voltage",
        "name": "Phase 3 voltage",
        "unit_of_measurement": "V",
        "value_template": "{{value_json.pvgridvoltage3| float / 10 }}",
    },
    "pvgridcurrent": {
        "state_class": "measurement",
        "device_class": "current",
        "name": "Phase 1 current",
        "unit_of_measurement": "A",
        "value_template": "{{value_json.pvgridcurrent| float / 10 }}",
    },
    "pvgridcurrent2": {
        "state_class": "measurement",
        "device_class": "current",
        "name": "Phase 2 current",
        "unit_of_measurement": "A",
        "value_template": "{{value_json.pvgridcurrent2| float / 10 }}",
    },
    "pvgridcurrent3": {
        "state_class": "measurement",
        "device_class": "current",
        "name": "Phase 3 current",
        "unit_of_measurement": "A",
        "value_template": "{{value_json.pvgridcurrent3| float / 10 }}",
    },
    "pvgridpower": {
        "state_class": "measurement",
        "device_class": "power",
        "name": "Phase 1 power",
        "unit_of_measurement": "kW",
        "value_template": "{{value_json.pvgridpower| float / 10000 }}",
    },
    "pvgridpower2": {
        "state_class": "measurement",
        "device_class": "power",
        "name": "Phase 2 power",
        "unit_of_measurement": "kW",
        "value_template": "{{value_json.pvgridpower2| float / 10000 }}",
    },
    "pvgridpower3": {
        "state_class": "measurement",
        "device_class": "power",
        "name": "Phase 3 power",
        "unit_of_measurement": "kW",
        "value_template": "{{value_json.pvgridpower3| float / 10000 }}",
    },
    # End grid
    "pvenergytoday": {
        "state_class": "total",
        "device_class": "energy",
        "name": "Generated energy (Today)",
        "unit_of_measurement": "kWh",
        "value_template": "{{value_json.pvenergytoday| float / 10 }}",
        "icon": "mdi:solar-power",
    },
    "epvtoday": {
        "name": "PV Energy today (Today)",
        "state_class": "total",
        "device_class": "energy",
        "unit_of_measurement": "kWh",
        "icon": "mdi:solar-power",
    },
    "epv1today": {
        "name": "Solar PV1 production",
        "state_class": "total",
        "device_class": "energy",
        "unit_of_measurement": "kWh",
        "icon": "mdi:solar-power",
    },
    "epv2today": {
        "name": "Solar PV2 production",
        "state_class": "total",
        "device_class": "energy",
        "unit_of_measurement": "kWh",
        "icon": "mdi:solar-power",
    },
    "pvenergytotal": {
        "state_class": "total_increasing",
        "device_class": "energy",
        "name": "Generated energy (Total)",
        "unit_of_measurement": "kWh",
        "value_template": "{{value_json.pvenergytotal| float / 10 }}",
        "icon": "mdi:solar-power",
    },
    "epvtotal": {
        "name": "Generated PV energy (Total)",
        "device_class": "energy",
        "unit_of_measurement": "kWh",
        "icon": "mdi:solar-power",
        "state_class": "total",
    },
    "epv1total": {
        "name": "Solar PV1 production (Total)",
        "state_class": "total",
        "device_class": "energy",
        "unit_of_measurement": "kWh",
        "icon": "mdi:solar-power",
    },
    "epv2total": {
        "name": "Solar PV2 production (Total)",
        "state_class": "total",
        "device_class": "energy",
        "unit_of_measurement": "kWh",
        "icon": "mdi:solar-power",
    },
    # For SPH compatiblity
    "epvTotal": {
        "name": "Generated PV energy (Today)",
        "device_class": "energy",
        "unit_of_measurement": "kWh",
        "value_template": "{{value_json.epvTotal| float / 10 }}",
        "icon": "mdi:solar-power",
        "state_class": "total",
    },
    "pactogridr": {
        "state_class": "measurement",
        "device_class": "energy",
        "name": "Energy export (Today)",
        "unit_of_measurement": "kWh",
        "value_template": "{{value_json.pactogridr| float / 10 }}",
        "icon": "mdi:solar-power",
    },
    "pactogridtot": {
        "device_class": "energy",
        "name": "Energy export (Total)",
        "unit_of_measurement": "kWh",
        "value_template": "{{value_json.pactogridtot| float / 10 }}",
        "icon": "mdi:solar-power",
        "state_class": "total",
    },
    "pvstatus": {
        "name": "State",
        # "value_template": "{% if value_json.pvstatus == 0 %}Standby{% elif value_json.pvstatus == 1 %}Normal{% elif value_json.pvstatus == 2 %}Fault{% else %}Unknown{% endif %}",
        "icon": "mdi:power-settings",
    },
    "totworktime": {
        "name": "Working time",
        "device_class": "duration",
        "unit_of_measurement": "hours",
        "value_template": "{{ value_json.totworktime| float / 7200 | round(2) }}",
    },
    "pvtemperature": {
        "state_class": "measurement",
        "device_class": "temperature",
        "name": "Inverter temperature",
        "unit_of_measurement": "°C",
        "value_template": "{{value_json.pvtemperature| float / 10 }}",
    },
    "pvipmtemperature": {
        "name": "IPM temperature",
        "device_class": "temperature",
        "unit_of_measurement": "°C",
        "value_template": "{{value_json.pvipmtemperature| float / 10 }}",
        "state_class": "measurement",
    },
    "pvboottemperature": {
        "device_class": "temperature",
        "name": "Inverter boost temperature",
        "unit_of_measurement": "°C",
        "value_template": "{{value_json.pvboottemperature| float / 10 }}",
        "state_class": "measurement",
    },
    "pvboosttemp": {
        "device_class": "temperature",
        "name": "Inverter boost temperature",
        "unit_of_measurement": "°C",
        "value_template": "{{value_json.pvboosttemp| float / 10 }}",
        "state_class": "measurement",
    },
    "etogrid_tod": {
        "device_class": "energy",
        "name": "Energy to grid (Today)",
        "unit_of_measurement": "kWh",
        "value_template": "{{value_json.etogrid_tod| float / 10 }}",
        "icon": "mdi:transmission-tower-import",
        "state_class": "total",
    },
    "etogrid_tot": {
        "device_class": "energy",
        "name": "Energy to grid (Total)",
        "unit_of_measurement": "kWh",
        "value_template": "{{value_json.etogrid_tot| float / 10 }}",
        "icon": "mdi:transmission-tower-import",
        "state_class": "total_increasing",
    },
    "etouser_tod": {
        "device_class": "energy",
        "name": "Import from grid (Today)",
        "unit_of_measurement": "kWh",
        "value_template": "{{value_json.etouser_tod| float / 10 }}",
        "icon": "mdi:solar-power",
        "state_class": "total",
    },
    "etouser_tot": {
        "device_class": "energy",
        "name": "Import from grid (Total)",
        "unit_of_measurement": "kWh",
        "value_template": "{{value_json.etouser_tot| float / 10 }}",
        "icon": "mdi:transmission-tower-export",
        "state_class": "total_increasing",
    },
    "pactouserr": {
        "name": "Import from grid (Actual)",
        "device_class": "power",
        "unit_of_measurement": "kW",
        "value_template": "{{value_json.pactouserr| float / 10 }}",
        "icon": "mdi:transmission-tower-export",
    },
    # Register 1015 # TODO: investiagate
    # "pactousertot": {
    #     "name": "Power consumption total",
    #     "device_class": "power",
    #     "unit_of_measurement": "kW",
    #     "icon": "mdi:transmission-tower-export",
    # },
    "elocalload_tod": {
        "device_class": "energy",
        "name": "Load consumption (Today)",
        "unit_of_measurement": "kWh",
        "value_template": "{{value_json.elocalload_tod| float / 10 }}",
        "icon": "mdi:solar-power",
        "state_class": "total",
    },
    "elocalload_tot": {
        "device_class": "energy",
        "name": "Load consumption (Total)",
        "unit_of_measurement": "kWh",
        "value_template": "{{value_json.elocalload_tot| float / 10 }}",
        "icon": "mdi:solar-power",
        "state_class": "total_increasing",
    },
    "plocaloadr": {
        "name": "Local load consumption",
        "device_class": "power",
        "unit_of_measurement": "kW",
        "value_template": "{{value_json.plocaloadr| float / 10 }}",
        "icon": "mdi:transmission-tower-export",
    },
    "grott_last_push": {
        "device_class": "timestamp",
        "name": "Grott last data push",
        "value_template": "{{value_json.grott_last_push}}",
    },
    "grott_last_measure": {
        "device_class": "timestamp",
        "name": "Last measure",
    },
    # batteries
    "eacharge_today": {
        "device_class": "energy",
        "name": "Battery charge from AC (Today)",
        "unit_of_measurement": "kWh",
        "icon": "mdi:battery-arrow-up",
        "state_class": "total",
    },
    "eacharge_total": {
        "device_class": "energy",
        "name": "Battery charge from AC (Today)",
        "unit_of_measurement": "kWh",
        "icon": "mdi:solar-power",
        "state_class": "total_increasing",
    },
    "vbat": {
        "state_class": "measurement",
        "device_class": "voltage",
        "name": "Battery voltage",
        "unit_of_measurement": "V",
    },
    "SOC": {
        "name": "Battery charge",
        "device_class": "battery",
        "state_class": "measurement",
        "unit_of_measurement": "%",
        "icon": "mdi:battery-charging-60",
    },
    # taken from register 1048 of RTU manual v1.20
    "batterytype": {
        "name": "Batteries type",
        "value_template": "{% if value_json.batterytype == 0 %}Lithium{% elif value_json.batterytype == '1' %}Lead-acid{% elif value_json.batterytype == '2' %}Other{% else %}Unknown{% endif %}",
        "icon": "mdi:power-settings",
    },
    "p1charge1": {
        "name": "Battery charge",
        "device_class": "power",
        "unit_of_measurement": "kW",
        "state_class": "measurement",
        "icon": "mdi:battery-arrow-up",
    },
    "eharge1_tod": {
        "name": "Battery charge (Today)",
        "device_class": "energy",
        "state_class": "total",
        "unit_of_measurement": "kWh",
        "icon": "mdi:battery-arrow-up",
    },
    "eharge1_tot": {
        "name": "Battery charge (Total)",
        "device_class": "energy",
        "state_class": "total_increasing",
        "unit_of_measurement": "kWh",
        "icon": "mdi:battery-arrow-up",
    },
    "edischarge1_tod": {
        "name": "Battery discharge (Today)",
        "device_class": "energy",
        "state_class": "total",
        "unit_of_measurement": "kWh",
        "icon": "mdi:battery-arrow-down",
    },
    "edischarge1_tot": {
        "name": "Battery discharge (Total)",
        "device_class": "energy",
        "state_class": "total_increasing",
        "unit_of_measurement": "kWh",
        "icon": "mdi:battery-arrow-down",
    },
    "battemp": {
        "name": "Battery temperature",
        "device_class": "temperature",
        "unit_of_measurement": "°C",
        "icon": "mdi:thermometer",
    },
    "spbusvolt": {
        "state_class": "measurement",
        "device_class": "voltage",
        "name": "BP bus voltage",
        "unit_of_measurement": "V",
    },
    "systemfaultword1": {
        "name": "System fault register 1",
    },
    "systemfaultword2": {
        "name": "System fault register 2",
    },
    "systemfaultword3": {
        "name": "System fault register 3",
    },
    "systemfaultword4": {
        "name": "System fault register 4",
    },
    "systemfaultword5": {
        "name": "System fault register 5",
    },
    "systemfaultword6": {
        "name": "System fault register 6",
    },
    "systemfaultword7": {
        "name": "System fault register 7",
    },
    "vpv1": {
        "state_class": "measurement",
        "device_class": "voltage",
        "name": "PV1 Voltage",
        "unit_of_measurement": "V",
        "value_template": "{{value_json.pv1voltage| float / 10 }}",
    },
    "vpv2": {
        "state_class": "measurement",
        "device_class": "voltage",
        "name": "PV2 Voltage",
        "unit_of_measurement": "V",
        "value_template": "{{value_json.pv1voltage| float / 10 }}",
    },
    "ppv1": {
        "name": "PV1 charge power",
        "device_class": "power",
        "unit_of_measurement": "W",
        "state_class": "measurement",
    },
    "ppv2": {
        "name": "PV1 charge power",
        "device_class": "power",
        "unit_of_measurement": "W",
        "state_class": "measurement",
    },
    "buck1curr": {
        "name": "Buck1 current",
        "device_class": "current",
        "unit_of_measurement": "A",
        "state_class": "measurement",
    },
    "buck2curr": {
        "name": "Buck2 current",
        "device_class": "current",
        "unit_of_measurement": "A",
        "state_class": "measurement",
    },
    "op_watt": {
        "name": "Output active power",
        "device_class": "power",
        "unit_of_measurement": "W",
        "state_class": "measurement",
    },
    "op_va": {
        "name": "Output apparent power",
        "device_class": "apparent_power",
        "unit_of_measurement": "VA",
        "state_class": "measurement",
    },
}


def make_payload(
    conf: Conf, device: str, device_class: str, name: str, key: str, unit: str = None
):
    # Default configuration payload
    payload = {
        "name": "{device} {name}",
        "unique_id": f"grott_{device}_{key}",  # Generate a unique device ID
        "state_topic": f"homeassistant/grott/{device}/state",
        "device": {
            "identifiers": [device],  # Group under a device
            "name": device,
            "manufacturer": "GrowWatt",
        },
        "value_template": f"{{{{ value_json.{key} }}}}",
    }

    # If there's a custom mapping add the new values
    if key in mapping:
        payload.update(mapping[key])

    if not payload["name"].startswith("{device} "):
        # Prepend the {device} template, prevent repeating
        payload["name"] = "{device} " + payload["name"]

    # Generate the name of the key, with all the param available
    payload["name"] = payload["name"].format(
        device=device, device_class=device_class, name=name, key=key
    )
    # HA automatically group the sensor if the device name is prepended

    # Reuse the existing divide value if available and not existing
    # and apply it to the HA config
    layout = conf.recorddict[conf.layout]
    if key in layout:
        if layout[key].get("type", "") == "num" and layout[key].get("divide"):
            if "value_template" not in payload:
                payload[
                    "value_template"
                ] = "{{{{value_json.{key} | float / {divide} }}}}".format(
                    key=key,
                    divide=layout[key].get("divide"),
                )
    return payload


class MqttStateHandler:
    __pv_config = {}
    client_name = "Grott - HA"

    @classmethod
    def is_configured(cls, serial: str):
        return cls.__pv_config.get(serial, False)

    @classmethod
    def set_configured(cls, serial: str):
        cls.__pv_config[serial] = True


def process_conf(conf: Conf):
    required_params = [
        "ha_mqtt_host",
        "ha_mqtt_port",
    ]
    if not all([param in conf.extvar for param in required_params]):
        print("Missing configuration for ha_mqtt")
        raise AttributeError

    if "ha_mqtt_user" in conf.extvar:
        auth = {
            "username": conf.extvar["ha_mqtt_user"],
            "password": conf.extvar["ha_mqtt_password"],
        }
    else:
        auth = None

    # Need to convert the port if passed as a string
    port = conf.extvar["ha_mqtt_port"]
    if isinstance(port, str):
        port = int(port)
    return {
        "client_id": MqttStateHandler.client_name,
        "auth": auth,
        "hostname": conf.extvar["ha_mqtt_host"],
        "port": port,
    }


def publish_single(conf: Conf, topic, payload, retain=False):
    conf = process_conf(conf)
    return single(topic, payload=payload, retain=retain, **conf)


def publish_multiple(conf: Conf, msgs):
    conf = process_conf(conf)
    return multiple(msgs, **conf)


def grottext(conf: Conf, data: str, jsonmsg: str):
    """Allow to push to HA MQTT bus, with auto discovery"""

    required_params = [
        "ha_mqtt_host",
        "ha_mqtt_port",
    ]
    if not all([param in conf.extvar for param in required_params]):
        pr("Missing configuration for ha_mqtt")
        return 1

    # Need to decode the json string
    jsonmsg = json.loads(jsonmsg)

    if jsonmsg.get("buffered") == "yes":
        # Skip buffered message, HA don't support them
        if conf.verbose:
            pr("\t - Grott HA - skipped buffered")
        return 5

    device_serial = jsonmsg["device"]
    values = jsonmsg["values"]

    # Send the last push in UTC with TZ
    dt = datetime.now(timezone.utc)
    # Add a new value to the existing values
    values["grott_last_push"] = dt.isoformat()

    # Layout can be undefined
    if not MqttStateHandler.is_configured(device_serial) and getattr(
        conf, "layout", None
    ):
        configs_payloads = []
        pr(f"\tGrott HA {__version__} - creating {device_serial} config in HA")
        for key in values.keys():
            # Generate a configuration payload
            payload = make_payload(conf, device_serial, "", key, key)
            if not payload:
                print(f"\t[Grott HA] {__version__} skipped key: {key}")
                continue

            try:
                topic = config_topic.format(
                    sensor_type="sensor",
                    device=device_serial,
                    attribut=key,
                )
                configs_payloads.append(
                    {
                        "topic": topic,
                        "payload": json.dumps(payload),
                        "retain": True,
                    }
                )
            except Exception as e:
                print(
                    f"\t - [grott HA] {__version__} Exception while creating new sensor {key}: {e}"
                )
                return 6

        # Create a virtual last_push key to allow tracking when there was the last data transmission

        try:
            key = "grott_last_push"
            payload = make_payload(conf, device_serial, "", key, key)
            topic = config_topic.format(
                sensor_type="sensor",
                device=device_serial,
                attribut=key,
            )
            configs_payloads.append(
                {
                    "topic": topic,
                    "payload": json.dumps(payload),
                    "retain": True,
                }
            )
        except Exception as e:
            print(
                f"\t - [grott HA] {__version__} Exception while creating new sensor last push: {e}"
            )
            return 4
        publish_multiple(conf, configs_payloads)
        # Now it's configured, no need to come back
        MqttStateHandler.set_configured(device_serial)

    if not MqttStateHandler.is_configured(device_serial):
        print(f"\t[Grott HA] {__version__} Can't configure device: {device_serial}")
        return 7

    # Push the vales to the topics
    try:
        publish_single(
            conf, state_topic.format(device=device_serial), json.dumps(values)
        )
    except Exception as e:
        print("[HA ext] - Exception while publishing - {}".format(e))
        # Reset connection state in case of problem
        return 2
    return 0

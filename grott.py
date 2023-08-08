"""
Grott Growatt monitor based on TCPIP sniffing or proxy (new 2.0)

    * Monitor needs to run on a (linux) system that is abble to see TCP/IP that
      is sent from inverter to Growatt Server
    * In the TCPIP sniffer mode this can be achieved by rerouting the growatt
      WIFI data via a Linux server with port forwarding
    * For more information how to see aditional documentation on GitHub
    * Monitor can run in forground and as a standard service!
    * For version history see: version_history.txt

Updated: 2023-03-17
"""


import sys

from grottconf import Conf
from grotthelpers import pr
from grottproxy import Proxy
from grottserver import Server
from grottsniffer import Sniff

VERREL = "2.8.2"


def main():
    # proces config file
    conf = Conf(VERREL)

    # print configuration
    if conf.verbose:
        conf.print()

    # To test config only remove # below
    # sys.exit(1)

    if conf.mode == "proxy":
        proxy = Proxy(conf)
        proxy.main(conf)

    elif conf.mode == "sniff":
        sniff = Sniff(conf)
        try:
            sniff.main(conf)
        except KeyboardInterrupt:
            pr("Ctrl C - Stopping server")
            sys.exit(1)

    elif conf.mode == "server":
        server = Server(conf)
        server.main(conf)

    else:
        pr("- Grott undefined mode")


if __name__ == "__main__":
    main()

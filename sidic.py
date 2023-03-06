#    _____    ___
#   / __(_)__/ (_)___
#  _\ \/ / _  / / __/
# /___/_/\_,_/_/\__/
#
# Sidic - A lightweight attack mitigation service designed for idc
# Made by Syuu (https://github.com/syuukr)

from yaml import load, SafeLoader
from os import path, makedirs, listdir, _exit
from time import sleep, time, localtime, strftime
from threading import Thread, Lock
from re import compile
from scapy.all import sniff
from requests import get

class Sidic:
    def __init__(self):
        build = 230227
        development = True
        if development == True:
            print("* This is develoption build, it might have some bugs")
        print(self.getLogo())
        print("Build: %d\n" % build)
        if not path.isfile("./config.yml"):
            config = """#    _____    ___
#   / __(_)__/ (_)___
#  _\ \/ / _  / / __/
# /___/_/\_,_/_/\__/
#
# Sidic - A lightweight attack mitigation service designed for idc
# Made by Syuu (https://github.com/syuukr)
sidic:
    # On to save logs, off to don't save logs
    # Log files are located in /logs
    logging: on
    mitigation:
        # On to mitigate idc from tcp attack, off to don't mitigate idc from tcp attack.
        tcp: on
        # On to mitigate idc from udp attack, off to don't mitigate idc from udp attack.
        udp: on
        # Interval between checking pps (0.1, 0.5, 1)
        # Lower interval makes mitigation faster, but may reduce accurancy and will requires more compute resources
        # Recommands to use with 1
        interval: 1
        # Duration by seconds to block attack considered ports
        duration: 60
        threshold:
            # Minimum tcp pps threshold per port to consider port is under tcp attack
            tcp: 100
            # Minimum udp pps threshold per port to consider port is under udp attack
            udp: 100"""
            with open("./config.yml", "w") as self.config:
                self.config.write(config)
        with open("./config.yml") as self.config:
            self.config = load(self.config, Loader=SafeLoader)

        self.logging = self.getState("logging")
        self.date = strftime("%Y-%m-%d", localtime(time()))

        if self.logging == True and not path.isdir("./logs"):
            makedirs("./logs")

        if not path.isdir("./ports"):
            makedirs("./ports")

        self.blocked = []
        self.duration = self.getDuration()
        self.interval = self.getInterval()
        self.tcp = self.getState("tcp"), self.getThreshold("tcp")
        self.udp = self.getState("udp"), self.getThreshold("udp")

        if self.tcp[0] == False and self.udp[0] == False:
            self.log("ERROR", "TCP and UDP mitigation can't be disabled at the same time")

    def start(self):
        try:
            cleanerThread = Thread(target=self.blockedCleaner)
            cleanerThread.start()
            while True:
                ports = listdir("./ports")
                if not len(ports) == 0:
                    threadList = []
                    for i in ports:
                        detectorThread = Thread(target=self.attacksDetector, args=(int(i),))
                        detectorThread.start()
                        threadList.append(detectorThread)
                    for t in threadList:
                        t.join()
                    sleep(self.interval)
        except Exception as e:
            self.log("ERROR", e)

    def attacksDetector(self, port):
        try:
            if port not in self.blocked:
                pps = self.getPps(port, self.interval)
                if self.interval == 0.5:
                    pps = pps[0] * 2, pps[1] * 2
                elif self.interval == 0.1:
                    pps = pps[0] * 10, pps[1] * 10
                else:
                    pps = pps[0], pps[1]
                if self.tcp[0] == True and pps[0] >= self.tcp[1] and port not in self.blocked:
                    self.blocked.append(port)
                    self.log("WARN", "Port %s blocked due to TCP threshold exceed (Last pps: %s / Blocked list: %s)" % (port, pps[0], str(self.blocked).removeprefix("[").removesuffix("]")))
                elif self.udp[0] == True and pps[1] >= self.udp[1] and port not in self.blocked:
                    self.blocked.append(port)
                    self.log("WARN", "Port %s blocked due to UDP threshold exceed (Last pps: %s / Blocked list: %s)" % (port, pps[1], str(self.blocked).removeprefix("[").removesuffix("]")))
        except Exception as e:
            self.log("ERROR", e)

    def blockedCleaner(self):
        try:
            while True:
                sleep(self.duration)
                if not len(self.blocked) == 0:
                    self.log("INFO", "Port %s has been removed from blocked list" % str(self.blocked).removeprefix("[").removesuffix("]"))
                    self.blocked.clear()
        except Exception as e:
            self.log("ERROR", e)

    def getPps(self, port, interval):
        try:
            rule = "dst port %d" % port
            measured = compile(r"TCP:(\d+) UDP:(\d+)").search(str(sniff(filter=rule, timeout=interval)))
            tcp = int(measured.group(1))
            udp = int(measured.group(2))
            return tcp, udp
        except Exception as e:
            self.log("ERROR", e)

    def getState(self, request):
        try:
            if request == "logging":
                return self.config["sidic"]["logging"]
            return self.config["sidic"]["mitigation"][request]
        except Exception as e:
            self.log("ERROR", e)

    def getThreshold(self, protocol):
        try:
            threshold = self.config["sidic"]["mitigation"]["threshold"][protocol]
            return threshold
        except Exception as e:
            self.log("ERROR", e)

    def getDuration(self):
        try:
            duration = self.config["sidic"]["mitigation"]["duration"]
            return duration
        except Exception as e:
            self.log("ERROR", e)

    def getInterval(self):
        try:
            interval = self.config["sidic"]["mitigation"]["interval"]
            if interval in [1, 0.5, 0.1, 1.0]:
                return float(interval)
            self.log("ERROR", "Interval must be 1 or 0.5 or 0.1")
        except Exception as e:
            self.log("ERROR", e)

    def log(self, level, message):
        try:
            datefull = strftime("%Y-%m-%d %H:%M:%S", localtime(time()))
            format = "[%s] %s: %s" % (datefull, level, message)
            if self.logging == True:
                with open("./logs/%s.log" % self.date, "a") as self.logfile:
                    self.logfile.write(format + "\n")
            print(format)
            if level == "ERROR":
                _exit(1)
        except Exception as e:
            print("ERROR: %s" % e)
            _exit(1)

    def getLogo(self):
        try:
            logo = """   _____    ___
  / __(_)__/ (_)___
 _\ \/ / _  / / __/
/___/_/\_,_/_/\__/

Sidic - A lightweight attack mitigation service designed for idc
"""
            credits = "Made by Syuu (https://github.com/syuukr)"
            return logo + credits
        except Exception as e:
            self.log("ERROR", e)

if __name__ == "__main__":
    try:
        sidic = Sidic()
        sidic.start()
    except KeyboardInterrupt:
        _exit(0)
    except Exception as e:
        print("ERROR: %s" % e)
        _exit(1)
from __future__ import print_function

import getpass
import sys
import re
import time
import json
import os

from optparse import OptionParser
from threading import Thread
from colored import fg
from configparser import ConfigParser

from minecraft import authentication
from minecraft.exceptions import YggdrasilError
from minecraft.networking.connection import Connection
from minecraft.networking.packets import Packet, clientbound, serverbound

viewing = None

class Config:
    cfg = """[Accounts]
file = accounts.txt

[AutoReconnect]
on = True
wait_time = 5

[onJoin]
command = /server ice
wait_time = 5 

[Server]
ip = play.pvpwars.net
port = 25565

[Login]
login_wait_time = 10
"""
    config = ConfigParser()

    try:
        open("accounts.txt")
    except:
        open("accounts.txt", "w", encoding="utf-8", errors="ignore").write("")

    try:
        open("config.cfg")
    except:
        open("config.cfg", "w", encoding="utf-8", errors="ignore").write(cfg)
        print(f"{fg('white')}Please configure your config file. Press ENTER to exit.")
        input()
        sys.exit()

    config.read("config.cfg")

    accounts_file = str(config["Accounts"]["file"])

    autoreconnect_on = True if str(config["AutoReconnect"]["on"]).lower().__contains__("true") else False
    autoreconnect_wait_time = int(config["AutoReconnect"]["wait_time"])

    onjoin_command = str(config["onJoin"]["command"])
    onjoin_wait_time = int(config["onJoin"]["wait_time"])

    server_ip = str(config["Server"]["ip"])
    port = int(config["Server"]["port"])

    login_login_wait_time = int(config["Login"]["login_wait_time"])


class Colors:
    colors = {
        "black": fg("#000000"),
        "dark_blue": fg("#0000AA"),
        "dark_green": fg("#00AA00"),
        "dark_aqua": fg("#00AAAA"),
        "dark_red": fg("#AA0000"),
        "dark_purple": fg("#AA00AA"),
        "gold": fg("#FFAA00"),
        "gray": fg("#AAAAAA"),
        "dark_gray": fg("#555555"),
        "blue": fg("#5555FF"),
        "green": fg("#55FF55"),
        "aqua": fg("#55FFFF"),
        "red": fg("#FF5555"),
        "light_purple": fg("#FF55FF"),
        "yellow": fg("#FFFF55"),
        "white": fg("#FFFFFF")
    }

class Chat:
    def __init__(self, user = None):

        self.users = []
        self.user = user

    def handleChatMessage(self, packet):
        global viewing

        if str(viewing) == str(self.user):
            try:

                words = json.loads(str(packet.json_data))["extra"]

                message = []

                for i in words:

                    if list(i.keys()).__contains__("color"):

                        try:

                            message.append(f"{Colors.colors[i['color']]}{i['text']}")

                        except Exception as e:

                            print(e)

                    else:

                        message.append(f"{fg('white')}{i['text']}")

                print("".join(message))

            except:

                print(json.loads(str(packet.json_data)))

    def sendChatMessage(self):
        global viewing

        self.users = Connect.connections.keys()

        while True:
            text = input()

            if text.__contains__(".view"):
                user = text.split(" ")[1]

                if user in self.users:
                    viewing = user
                    print(f"{fg('white')}Switched chat view to {user}.")

                else:
                    print(f"{fg('white')}Invalid user, make sure to type the email.")

            elif text.__contains__(".switch"):
                user = text.split(" ")[1]

                if user in self.users:
                    viewing = user
                    print(f"{fg('white')}Switched chat view to {user}.")

                else:
                    print(f"{fg('white')}Invalid user, make sure to type the email.")

            elif viewing in self.users:
                packet = serverbound.play.ChatPacket()
                packet.message = text
                Connect.connections[viewing].write_packet(packet)

class Login:
    def __init__(self, email, password):

        self.email = email

        self.password = password

    def authenticate(self):

        auth_token = authentication.AuthenticationToken()

        try:
            auth_token.authenticate(self.email, self.password)
            return auth_token

        except YggdrasilError as e:
            input(e)
            sys.exit()

class Connect:

    connections = {

    }

    def __init__(self, ip, port, authtoken, email, passw):

        self.ip = ip

        self.port = port

        self.authtoken = authtoken

        self.email = email

        self.passw = passw

    def connect(self):
        global viewing

        if viewing is None:
            viewing = self.email

        Connect.connections[str(self.authtoken.username)] = Connection(self.ip, self.port, auth_token=self.authtoken)

        connection = Connect.connections[str(self.authtoken.username)]

        def onjoin(packet):

            print(f"{Colors.colors['green']}[+] Connected as {self.authtoken.username}")

            time.sleep(Config.onjoin_wait_time)

            p = serverbound.play.ChatPacket()
            p.message = Config.onjoin_command
            connection.write_packet(p)

        connection.register_packet_listener(onjoin, clientbound.play.JoinGamePacket)

        c = Chat(self.email)
        connection.register_packet_listener(c.handleChatMessage, clientbound.play.ChatMessagePacket)

        if Config.autoreconnect_on:
            d = Disconnect(self.email, self.passw)
            connection.register_packet_listener(d.handleDisconnect, clientbound.play.DisconnectPacket)

        connection.connect()

class Disconnect:
    def __init__(self, email, passw):
        self.email = email
        self.passw = passw

    def handleDisconnect(self, packet):

        print(f'{fg("red")}[-] Disconnected')

        time.sleep(Config.autoreconnect_wait_time)

        l = Login(self.email, self.passw)
        token = l.authenticate()

        c = Connect(Config.server_ip, Config.port, token, self.email, self.passw)
        c.connect()
        print(f'{Colors.green}[+] Connected as {token.username}')

def join(email, passw):
    l = Login(email, passw)
    token = l.authenticate()

    c = Connect(Config.server_ip, Config.port, token, email, passw)
    c.connect()

def main():

    t = Thread(target=Chat().sendChatMessage)

    for i in open(Config.accounts_file, encoding="utf-8", errors="ignore").read().split("\n"):
        time.sleep(Config.login_login_wait_time)
        try:

            email = i.split(":")[0]
            passw = i.split(":")[1]

            Thread(target=join, args=(email, passw, )).start()


        except Exception as e:
            print(e)

    t.start()
    t.join()


if __name__ == "__main__":
    main()

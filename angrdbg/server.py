#!/usr/bin/env python
"""
classic rpyc server running a SlaveService + angrdbg + IPython shell
usage:
    angrdbg-srv.py                            # default settings
    angrdbg-srv.py --host HOST --port PORT    # custom settings

    # ssl-authenticated server (keyfile and certfile are required)
    angrdbg-srv.py --ssl-keyfile keyfile.pem --ssl-certfile certfile.pem --ssl-cafile cafile.pem
"""
import sys
import os
import rpyc
import threading
import signal
import Queue

from plumbum import cli
from rpyc.utils.server import Server
from rpyc.utils.classic import DEFAULT_SERVER_PORT, DEFAULT_SERVER_SSL_PORT
from rpyc.utils.registry import REGISTRY_PORT
from rpyc.utils.registry import UDPRegistryClient, TCPRegistryClient
from rpyc.utils.authenticators import SSLAuthenticator
from rpyc.lib import setup_logger
from rpyc.core import SlaveService

BANNER = "[angrdbg server v1.0]"

#######################
import angr
import claripy
import pyvex
import angrdbg
import IPython
#from angrdbg import *
#######################


class WeirdServer(Server):  # n1 threaded n2 forked

    def __init__(self, service, done_event, **kwargs):
        self.num_conns = 2
        self.thread = None
        self.proc = None
        self.done_event = done_event
        Server.__init__(self, service, **kwargs)

    @classmethod
    def _handle_sigchld(cls, signum, unused):
        try:
            while True:
                pid, dummy = os.waitpid(-1, os.WNOHANG)
                if pid <= 0:
                    break
        except OSError:
            pass
        # re-register signal handler (see man signal(2), under Portability)
        signal.signal(signal.SIGCHLD, cls._handle_sigchld)

    def _accept_method(self, sock):
        self.num_conns -= 1

        if self.num_conns == 1:
            t = threading.Thread(
                target=self._authenticate_and_serve_client,
                args=[sock])
            t.start()

            self.thread = t
        else:
            pid = os.fork()
            if pid == 0:
                # child
                try:
                    self.logger.debug("child process created")
                    # 76: call signal.siginterrupt(False) in forked child
                    signal.siginterrupt(signal.SIGCHLD, False)
                    self.listener.close()
                    self.clients.clear()
                    self._authenticate_and_serve_client(sock)
                except BaseException:
                    self.logger.exception(
                        "child process terminated abnormally")
                else:
                    self.logger.debug("child process terminated")
                finally:
                    self.logger.debug("child terminated")
                    os._exit(0)
            else:
                # parent
                self.proc = pid
                sock.close()

        if self.num_conns == 0:
            self.done_event.set()
            self.listener.close()
            self.join()

    def join(self):
        self.thread.join()

        try:
            pid, dummy = os.waitpid(self.proc, 0)  # os.WNOHANG)
        except OSError as ee:
            print ee


class AngrDbgServer(cli.Application):
    port = cli.SwitchAttr(["-p", "--port"], cli.Range(0, 65535), default=None,
                          help="The TCP listener port (default = %s, default for SSL = %s)" %
                          (DEFAULT_SERVER_PORT, DEFAULT_SERVER_SSL_PORT), group="Socket Options")
    host = cli.SwitchAttr(
        ["--host"],
        str,
        default="127.0.0.1",
        help="The host to bind to. "
        "The default is INADDR_ANY",
        group="Socket Options")
    ipv6 = cli.Flag(["--ipv6"], help="Enable IPv6", group="Socket Options")

    logfile = cli.SwitchAttr(
        "--logfile",
        str,
        default=None,
        help="Specify the log file to use; "
        "the default is stderr",
        group="Logging")
    quiet = cli.Flag(["-q",
                      "--quiet"],
                     help="Quiet mode (only errors will be logged)",
                     group="Logging")

    ssl_keyfile = cli.SwitchAttr(
        "--ssl-keyfile",
        cli.ExistingFile,
        help="The keyfile to use for SSL. Required for SSL",
        group="SSL",
        requires=["--ssl-certfile"])
    ssl_certfile = cli.SwitchAttr(
        "--ssl-certfile",
        cli.ExistingFile,
        help="The certificate file to use for SSL. Required for SSL",
        group="SSL",
        requires=["--ssl-keyfile"])
    ssl_cafile = cli.SwitchAttr(
        "--ssl-cafile",
        cli.ExistingFile,
        help="The certificate authority chain file to use for SSL. Optional; enables client-side "
        "authentication",
        group="SSL",
        requires=["--ssl-keyfile"])

    auto_register = cli.Flag(
        "--register",
        help="Asks the server to attempt registering with "
        "a registry server. By default, the server will not attempt to register",
        group="Registry")
    registry_type = cli.SwitchAttr(
        "--registry-type",
        cli.Set(
            "UDP",
            "TCP"),
        default="UDP",
        help="Specify a UDP or TCP registry",
        group="Registry")
    registry_port = cli.SwitchAttr(
        "--registry-port",
        cli.Range(
            0,
            65535),
        default=REGISTRY_PORT,
        help="The registry's UDP/TCP port",
        group="Registry")
    registry_host = cli.SwitchAttr(
        "--registry-host",
        str,
        default=None,
        help="The registry host machine. For UDP, the default is 255.255.255.255; "
        "for TCP, a value is required",
        group="Registry")

    def main(self):
        if self.registry_type == "UDP":
            if self.registry_host is None:
                self.registry_host = "255.255.255.255"
            self.registrar = UDPRegistryClient(
                ip=self.registry_host, port=self.registry_port)
        else:
            if self.registry_host is None:
                raise ValueError(
                    "With TCP registry, you must specify --registry-host")
            self.registrar = TCPRegistryClient(
                ip=self.registry_host, port=self.registry_port)

        if self.ssl_keyfile:
            self.authenticator = SSLAuthenticator(
                self.ssl_keyfile, self.ssl_certfile, self.ssl_cafile)
            default_port = DEFAULT_SERVER_SSL_PORT
        else:
            self.authenticator = None
            default_port = DEFAULT_SERVER_PORT
        if self.port is None:
            self.port = default_port

        setup_logger(self.quiet, self.logfile)

        sys.stdout.write(
            BANNER + " starting at %s %s\n" %
            (self.host, self.port))
        sys.stdout.flush()

        done_event = threading.Event()
        srv = WeirdServer(
            SlaveService,
            done_event,
            hostname=self.host,
            port=self.port,
            reuse_addr=True,
            ipv6=self.ipv6,
            authenticator=self.authenticator,
            registrar=self.registrar,
            auto_register=self.auto_register)

        t = threading.Thread(target=self._serve, args=[srv])
        t.start()

        # wait for 2 connections
        done_event.wait()

        IPython.embed(
            banner1=BANNER + " client connected\n",
            banner2="",  # "tip: call serve_all() on the client to have a full working shell here.",
            exit_msg=BANNER + " shell closed.\nexiting...\n"
        )

        os.kill(srv.proc, signal.SIGKILL)
        os._exit(0)

    def _serve(self, srv):
        srv.start()

        sys.stdout.write("\n" + BANNER + " client disconnected.\nexiting...\n")
        os._exit(0)


def main():
    AngrDbgServer.run()


'''simple client
import rpyc
import thread

conn1 = rpyc.classic.connect("localhost")
conn2 = rpyc.classic.connect("localhost")
thread.start_new_thread(conn2.serve_all, tuple())

'''

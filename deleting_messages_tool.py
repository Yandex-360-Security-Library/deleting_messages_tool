import argparse
import enum
import imaplib
import logging
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta
from http import HTTPStatus
from os import environ
from textwrap import dedent
from typing import Optional, Union

import requests
import urllib3
from pydantic import BaseModel, Field
from urllib3.exceptions import InsecureRequestWarning

urllib3.disable_warnings(InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("deleting messages")

DEFAULT_IMAP_SERVER = "imap.yandex.ru"
DEFAULT_IMAP_PORT = 993
DEFAULT_360_API_URL = "https://api360.yandex.net"
DEFAULT_OAUTH_API_URL = "https://oauth.yandex.ru/token"
OAUTH_TOKEN_ARG = "OAUTH_TOKEN"
ORGANIZATION_ID_ARG = "ORGANIZATION_ID"
APPLICATION_CLIENT_ID_ARG = "APPLICATION_CLIENT_ID"
APPLICATION_CLIENT_SECRET_ARG = "APPLICATION_CLIENT_SECRET"
EXIT_CODE = 1


def arg_parser():
    parser = argparse.ArgumentParser(
        description=dedent(
            f"""
            Script for searching emails with a subject for the
            last N days in yandex 360 organizations.

            Environment options:
            {OAUTH_TOKEN_ARG} - OAuth Token,
            {ORGANIZATION_ID_ARG} - Organization ID,
            {APPLICATION_CLIENT_ID_ARG} - WEB Application ClientID,
            {APPLICATION_CLIENT_SECRET_ARG} - WEB Application secret

            For example:
            {OAUTH_TOKEN_ARG}="AgAAgfAAAAD4beAkEsWrefhNeyN1TVYjGT1k",
            {ORGANIZATION_ID_ARG}=123,
            {APPLICATION_CLIENT_ID_ARG} = "123BbCc4Dd5Ee6FffFassadsaddas",
            {APPLICATION_CLIENT_SECRET_ARG} = "00b31ffFasse8a481eaaf75955c175a20f",
            """
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    def argument_range(value: str) -> int:
        try:
            if int(value) < 0 or int(value) > 90:
                raise argparse.ArgumentTypeError(
                    f"{value} is invalid. Valid values in range: [0, 90]"
                )
        except ValueError:
            raise argparse.ArgumentTypeError(f"'{value}' is not int value")
        return int(value)

    parser.add_argument(
        "--rfc-message-id", help="Message subject", type=str, required=True
    )
    parser.add_argument(
        "--date-ago",
        help="Number of days to review [0, 90]",
        type=argument_range,
        required=True,
    )

    return parser


def main():
    parsr = arg_parser()
    args = parsr.parse_args()
    try:
        settings = get_settings()
    except ValueError:
        logging.error("ERROR: The value of {ORGANIZATION_ID_ARG} must be an integer.")
        sys.exit(EXIT_CODE)
    except KeyError as key:
        logger.error(f"ERROR: Required environment vars not provided: {key}")
        parsr.print_usage()
        sys.exit(EXIT_CODE)
    rfc_id = args.rfc_message_id
    date_ago = args.date_ago
    logger.info("deleting_messages_tool started.")
    client = Client360(
        token=settings.oauth_token,
        org_id=settings.organization_id,
        client_id=settings.app_client_id,
        secret=settings.app_client_secret,
    )
    fetched_message = fetch_audit_logs(
        client=client, rfc_message_id=rfc_id, date_ago=date_ago
    )
    if not fetched_message.subject:
        logger.info("No message for delete.")
        logger.info("deleting_messages_tool finished.")
        return
    if is_deletion_approve(
        subject=fetched_message.subject, users=fetched_message.recipients
    ):
        process_recipients(
            client=client, recipients=fetched_message.recipients, rfc_id=rfc_id
        )
    logger.info("deleting_messages_tool finished.")


def process_recipients(client: "Client360", recipients: set, rfc_id: str):
    for recipient in recipients:
        user_token = client.user_token.get(user_mail=recipient)
        try:
            connector = connect_to_mail(
                username=recipient, access_token=user_token.access_token
            )
        except imaplib.IMAP4.error:
            logger.error(f"Connect to {recipient} failed.")
            continue
        logger.info(f"Connect to {recipient} success.")
        status, folders = connector.list()
        if status != "OK":
            logger.error("Folders process failed.")
            continue
        process_folders(connector=connector, folders=folders, rfc_id=rfc_id)
        connector.logout()


def process_folders(connector: imaplib.IMAP4_SSL, folders: list, rfc_id: str):
    for folder in folders:
        folder = map_folder(folder)
        if not folder:
            continue
        status, _ = connector.select(mailbox=folder, readonly=False)
        if status != "OK":
            logger.error("Folder selection failed.")
        del_status: DeletionStatus = delete(connector=connector, rfc_id=rfc_id)
        match del_status:
            case DeletionStatus.Deleted:
                logger.info(f"Message rfc id: {rfc_id} deleted.")
                break
            case DeletionStatus.Empty:
                logger.info(f"Empty folder {folder} ")
            case DeletionStatus.NotFound:
                logger.info(f"Message rfc id: {rfc_id} not found in folder: {folder}")


def delete(connector: imaplib.IMAP4_SSL, rfc_id: str) -> "DeletionStatus":
    status, messages = connector.search(None, "ALL")
    if not messages[0]:
        return DeletionStatus.Empty
    for num in messages[0].split():
        status, data = connector.fetch(num, "(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])")
        if status == "OK":
            if type(data[0]) is not tuple:
                continue
            headers = data[0][1]
            if rfc_id.encode() in headers:
                connector.store(num, "+FLAGS", "\\Deleted")
                return DeletionStatus.Deleted
    return DeletionStatus.NotFound


def map_folder(folder: Optional[bytes]) -> Optional[str]:
    if not folder:
        return None
    return folder.decode().split('"|"')[-1].strip().strip('""')


def get_settings():
    settings = SettingParams(
        oauth_token=environ[OAUTH_TOKEN_ARG],
        organization_id=int(environ[ORGANIZATION_ID_ARG]),
        app_client_id=environ.get(APPLICATION_CLIENT_ID_ARG, None),
        app_client_secret=environ.get(APPLICATION_CLIENT_SECRET_ARG, None),
    )
    return settings


def fetch_audit_logs(
    client: "Client360", rfc_message_id: str, date_ago: int
) -> "FetchedMessage":
    day_last_check = (
        datetime.now().replace(hour=0, minute=0, second=0) - timedelta(days=date_ago)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    fetched_message = FetchedMessage(subject=None, recipients=set())
    audit_log = client.audit_log.get(after_date=day_last_check)
    while True:
        for event in audit_log.events:
            if event.msgId[1:-1] == rfc_message_id:
                if not fetched_message.subject:
                    fetched_message.subject = event.subject
                fetched_message.recipients.add(event.userLogin)
        if audit_log.nextPageToken == "":
            break
        audit_log = client.audit_log.get(
            after_date=day_last_check, page_token=audit_log.nextPageToken
        )
    return fetched_message


def is_deletion_approve(subject: str, users: set) -> bool:
    print(f"| subject: {subject}")
    print("| recipients:")
    for user in users:
        print(f"| {user}")
    a = input("Input 'yes' to delete: ")
    if a.strip().lower() == "yes":
        return True
    return False


def generate_oauth(username, access_token):
    return ("user=%s\1auth=Bearer %s\1\1" % (username, access_token)).encode()


def connect_to_mail(username: str, access_token: str):
    imap_connector = imaplib.IMAP4_SSL(DEFAULT_IMAP_SERVER, DEFAULT_IMAP_PORT)
    imap_connector.authenticate(
        "XOAUTH2", lambda x: generate_oauth(username, access_token)
    )
    return imap_connector


class Client360:
    def __init__(self, token: str, org_id: int, client_id: str, secret: str):
        self._token = token
        self._org_id = org_id
        self._id = client_id
        self._secret = secret

    @property
    def audit_log(self):
        return AuditLogAPI(token=self._token, org_id=self._org_id)

    @property
    def user_token(self):
        return UserTokenAPI(client_id=self._id, secret=self._secret)


class AuditLogAPI:
    def __init__(self, token: str, org_id: int):
        self._token = token
        self._org_id = org_id

    def get(self, after_date: str, page_token: str = "0_0", verify: bool = False):
        url = f"{DEFAULT_360_API_URL}/security/v1/org/{self._org_id}/audit_log/mail"
        headers = {"Authorization": f"OAuth {self._token}"}
        params = {
            "pageSize": 100,
            "types": "message_receive",
            "afterDate": after_date,
            "pageToken": page_token,
        }
        response = requests.get(
            url, headers=headers, params=params, verify=verify
        )
        if response.status_code != HTTPStatus.OK.value:
            raise Client360Error(response.status_code)
        audit_log = AuditLog.parse_obj(response.json())
        return audit_log


class UserTokenAPI:
    def __init__(self, client_id: str, secret: str):
        self._id = client_id
        self._secret = secret

    def get(self, user_mail: str):
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": self._id,
            "client_secret": self._secret,
            "subject_token": user_mail,
            "subject_token_type": "urn:yandex:params:oauth:token-type:email",
        }
        response = requests.post(url=DEFAULT_OAUTH_API_URL, headers=headers, data=data)
        if response.status_code != HTTPStatus.OK.value:
            raise ClientOAuthError(response.status_code)
        return UserToken.parse_obj(obj=response.json())


class DeletionStatus(enum.Enum):
    NotFound = "Not Found"
    Empty = "Empty"
    Deleted = "Deleted"


@dataclass
class SettingParams:
    oauth_token: str
    organization_id: int
    app_client_id: str
    app_client_secret: str


@dataclass
class FetchedMessage:
    subject: Optional[str]
    recipients: set


class AuditLog(BaseModel):
    events: list[Union["AuditLogEvents"]]
    nextPageToken: str


def convert_datetime(date: str) -> datetime:
    return datetime.strptime(date, "%Y-%m-%d")


class AuditLogEvents(BaseModel):
    eventType: str
    orgId: int
    userUid: str
    userLogin: str
    userName: str
    requestId: str
    uniqId: str
    source: str
    clientIp: str
    date: datetime = convert_datetime
    mid: str
    folderName: str
    folderType: str
    labels: list
    msgId: str
    subject: str
    from_: str = Field("from")
    to: str
    cc: str
    bcc: str


class UserToken(BaseModel):
    access_token: str
    expires_in: int
    issued_token_type: str
    scope: str
    token_type: str


class ToolError(Exception):
    def __init__(self, *args):
        if args:
            self.msg = args[0]
        else:
            self.msg = None

    def __str__(self):
        return self.msg


class Client360Error(ToolError):
    def __str__(self):
        match self.msg:
            case 403:
                return 'No access rights to the resource.'
            case 401:
                return "Invalid user token."
            case _:
                return f"Unexpected status code: {self.msg}"


class ClientOAuthError(ToolError):
    def __str__(self):
        match self.msg:
            case 400:
                return "Invalid application client id or secret"
            case _:
                return f"Unexpected status code: {self.msg}"


if __name__ == "__main__":
    try:
        main()
    except ToolError as err:
        logging.error(err)
        sys.exit(EXIT_CODE)
    except Exception as exp:
        logging.exception(exp)
        sys.exit(EXIT_CODE)

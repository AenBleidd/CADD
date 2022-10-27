import hashlib
import ssl
import StringIO
import urllib2
import xml.sax as sax

class BoincService:
    """ This class wrap a single BOINC service. You should have one of this class
    for each BOINC Service you want to use.
    """

    def __init__(self):
        pass

    def authenticate(self, server, email, passwd):
        """ authenticate the user with the BOINC service """
        if server is None or not server or email is None or not email or passwd is None or not passwd:
            return "ERROR"

        self._server = server
        result, self._authenticator = self._boincAuth(email, passwd)

        return result

    def _boincAuth(self, email, passwd):
        """ authenticate the user with the BOINC service """
        passwd_hash = hashlib.md5(passwd + email.lower()).hexdigest()
        quoted_email = urllib2.quote(email)
        url = "lookup_account.php"
        params = "?email_addr=" + quoted_email + "&passwd_hash=" + passwd_hash

        result, data = self._do_request(url+params, None)

        if result:
            handler = RpcAccountOutHandler()
            self._parse_xml_reply(data, handler)
            if handler.authenticator is None:
                return "Error", None

            return "Authenticated successfully", handler.authenticator

        return "ERROR: " + data, None

    def _do_request(self, url, params):
        """ do a request to the BOINC service """
        address = self._server
        if not address.endswith("/"):
            address += "/"
        address += url

        # print("URL:" + address)

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        f = urllib2.urlopen(address, params, context=context)
        reply = f.read()
        # print(reply)

        error_num, error_msg = self._check_for_error(reply)
        if error_num is not None:
            return False, error_msg

        return True, reply

    def _check_for_error(self, reply):
        """ check if the reply contains an error """
        if reply is None or not reply:
            return None

        error_handler = RpcErrorHandler()
        self._parse_xml_reply(reply, error_handler)

        return error_handler.error_num, error_handler.error_msg

    def _parse_xml_reply(self, reply, handler):
        """ parse the reply from the BOINC service """
        if reply is None or not reply:
            return

        parser = sax.make_parser()
        parser.setContentHandler(handler)
        parser.parse(StringIO.StringIO(reply))

class RpcErrorHandler(sax.ContentHandler):
    def __init__(self):
        self.error_num = None
        self.error_msg = None
        self._current = None

    def startElement(self, name, attrs):
        self._current = name

    def endElement(self, name):
        self._current = None

    def characters(self, content):
        if self._current == "error_num":
            self.error_num = content
        elif self._current == "error_msg":
            self.error_msg = content

class RpcAccountOutHandler(sax.ContentHandler):
    def __init__(self):
        self.authenticator = None
        self._current = None

    def startElement(self, name, attrs):
        self._current = name

    def endElement(self, name):
        self._current = None

    def characters(self, content):
        if self._current == "authenticator":
            self.authenticator = content

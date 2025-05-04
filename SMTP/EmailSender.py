import base64
import os
import socket
import ssl


class EmailSender:
    def __init__(self, config_path):
        self.folder = os.path.dirname(config_path)
        self.config = self.parse_config(config_path)
        self.config['attachments'] = [os.path.join(self.folder, fname) for fname in self.config['attachments']]
        self.message_text = self.read_file(os.path.join(self.folder, "message.txt"))
        self.full_message = self.create_mime_message()

    @staticmethod
    def parse_config(path):
        config = {}
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                if ':' in line:
                    key, value = line.strip().split(':', 1)
                    config[key.strip()] = value.strip()
        config['to'] = [addr.strip() for addr in config.get('to', '').split(',')]
        config['attachments'] = [f.strip() for f in config.get('attachments', '').split(',') if f.strip()]
        return config

    @staticmethod
    def read_file(path, binary=False):
        with open(path, 'rb' if binary else 'r', encoding=None if binary else 'utf-8') as f:
            return f.read()

    @staticmethod
    def send_line(sock, text):
        sock.send((text + '\r\n').encode('utf-8'))

    @staticmethod
    def recv_all(sock):
        data = sock.recv(4096)
        return data.decode('utf-8')

    def encode_attachment(self, file_path):
        content = self.read_file(file_path, binary=True)
        return base64.encodebytes(content).decode('ascii')

    def create_mime_message(self):
        boundary = '===BOUNDARY==='
        lines = []
        lines.append(f"From: {self.config['from']}")
        lines.append(f"To: {', '.join(self.config['to'])}")
        lines.append(f"Subject: {self.config['subject']}")
        lines.append("MIME-Version: 1.0")
        lines.append(f'Content-Type: multipart/mixed; boundary="{boundary}"')
        lines.append("")
        lines.append(f"--{boundary}")
        lines.append("Content-Type: text/plain; charset=utf-8")
        lines.append("Content-Transfer-Encoding: 7bit")
        lines.append("")
        lines.append(self.message_text)
        lines.append("")
        for filename in self.config['attachments']:
            encoded = self.encode_attachment(filename)
            basename = os.path.basename(filename)
            lines.append(f"--{boundary}")
            lines.append("Content-Type: application/octet-stream; name=\"" + basename + "\"")
            lines.append("Content-Transfer-Encoding: base64")
            lines.append(f"Content-Disposition: attachment; filename=\"{basename}\"")
            lines.append("")
            lines.append(encoded)
            lines.append("")
        lines.append(f"--{boundary}--")
        lines.append("")
        return "\r\n".join(lines)

    def send_mail(self):
        context = ssl.create_default_context()
        with socket.create_connection((self.config['smtp_server'], int(self.config['smtp_port']))) as sock:
            with context.wrap_socket(sock, server_hostname=self.config['smtp_server']) as client:
                print(self.recv_all(client))
                self.send_line(client, f'EHLO localhost')
                print(self.recv_all(client))
                self.send_line(client, 'AUTH LOGIN')
                print(self.recv_all(client))
                self.send_line(client, base64.b64encode(self.config['from'].encode()).decode())
                print(self.recv_all(client))
                self.send_line(client, base64.b64encode(self.config['password'].encode()).decode())
                print(self.recv_all(client))
                self.send_line(client, f'MAIL FROM:<{self.config["from"]}>')
                print(self.recv_all(client))
                for recipient in self.config['to']:
                    self.send_line(client, f'RCPT TO:<{recipient}>')
                    print(self.recv_all(client))
                self.send_line(client, 'DATA')
                print(self.recv_all(client))
                client.send((self.full_message + "\r\n.\r\n").encode('utf-8'))
                print(self.recv_all(client))
                self.send_line(client, 'QUIT')
                print(self.recv_all(client))
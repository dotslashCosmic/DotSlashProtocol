#DotSlashTextProtocol - An HTTP Fork, to be merged with dsp
#Author: dotSlashCosmic
#Scheme syntax: dstp://<host>[:<port>]/
#lots todo

import json, threading

class dstp:
    def __init__(self, dsp):
        self.dsp = dsp
        self.cookies = {}

    def i(self, url):
        cookie_str = '; '.join(f'{k}={v}' for k, v in self.cookies.items())
        request = f"i {url} DSTP/v1\r\nH: {self.dsp.dest_ip}\r\nC: {cookie_str}\r\n\r\n"
        self.dsp.data = request
        self.dsp.dsp()

    def o(self, url, data):
        cookie_str = '; '.join(f'{k}={v}' for k, v in self.cookies.items())
        request = f"o {url} DSTP/v1\r\nH: {self.dsp.dest_ip}\r\nL: {len(data)}\r\nC: {cookie_str}\r\n\r\n{data}"
        self.dsp.data = request
        self.dsp.dsp()

    def receive(self):
        response = self.dsp.receive()
        header, body = response.split('\r\n\r\n', 1)
        headers = self.parse_headers(header)
        if 'Set-Cookie' in headers:
            self.update_cookies(headers['Set-Cookie'])
        return headers, self.parse_body(body, headers.get('Content-Type'))

    def parse_headers(self, header_str):
        lines = header_str.split('\r\n')
        headers = {}
        for line in lines[1:]:
            key, value = line.split(': ', 1)
            headers[key] = value
        return headers

    def parse_body(self, body_str, content_type):
        if 'application/json' in content_type:
            return json.loads(body_str)
        else:
            return body_str

    def update_cookies(self, cookie_str):
        cookies = cookie_str.split('; ')
        for cookie in cookies:
            key, value = cookie.split('=', 1)
            self.cookies[key] = value
          
class server:
    def __init__(self, dsp):
        self.dsp = dsp
        self.dstp = dstp(self.dsp)
        self.running = False

    def start(self):
        self.running = True
        server_thread = threading.Thread(target=self.run_server)
        server_thread.start()

    def stop(self):
        self.running = False

    def run_server(self):
        while self.running:
            try:
                headers, body = self.dstp.receive()
                if headers['Method'] == 'i':
                    response = self.handle_i(headers['Path'])
                elif headers['Method'] == 'o':
                    response = self.handle_o(headers['Path'], body)
                self.dsp.data = response
                self.dsp.dsp()
            except Exception as e:
                self.dsp.data = f"DSTP/v1 Server Error\r\n\r\n{str(e)}"
                self.dsp.dsp()

    def handle_get(self, path):
        try:
            with open(path, 'r') as file:
                data = file.read()
            return f"DSTP/v1 OK\r\n\r\n{data}"
        except FileNotFoundError:
            return "DSTP/v1 Not Found\r\n\r\nFile not found"
        except Exception as e:
            return f"DSTP/v1 Server Error\r\n\r\n{str(e)}"

    def handle_post(self, path, data):
        try:
            with open(path, 'w') as file:
                file.write(data)
            return "DSTP/v1 OK\r\n\r\nOK"
        except Exception as e:
            return f"DSTP/v1 Server Error\r\n\r\n{str(e)}"

              while self.running:
            try:
                headers, body = self.dstp.receive()
                if headers['Method'] == 'i':  # GET request
                    response = self.handle_i(headers['Path'])
                elif headers['Method'] == 'o':  # POST request
                    response = self.handle_o(headers['Path'], body)
                self.dsp.data = response
                self.dsp.dsp()
            except Exception as e:
                self.dsp.data = f"DSTP/v1 Server Error\r\n\r\n{str(e)}"
                self.dsp.dsp()

def run_tui():
    dsp = DSP(source_ip, dest_ip, source_port, dest_port, dest_mac, data)
    protocol = dstp(dsp)
    while True:
        print("\n1. Send GET request")
        print("2. Send POST request")
        print("3. Quit")
        choice = input("Enter your choice: ")
        if choice == '1':
            url = input("Enter the URL: ")
            protocol.i(url)
            headers, body = protocol.receive()
            print("Response:", headers, body)
        elif choice == '2':
            url = input("Enter the URL: ")
            data = input("Enter the data: ")
            protocol.o(url, data)
            headers, body = protocol.receive()
            print("Response:", headers, body)
        elif choice == '3':
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    run_tui()

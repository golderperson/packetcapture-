import pyshark


def analyze(data):# analyze http2 packet
    keywords = ('username', 'uname', 'user', 'login', 'Name',
                'password', 'pass', 'signin', 'signup', 'name', 'Value','email','user_id','user_data')#dictionary words
    for keyword in keywords:
        if keyword in data:
            start_index = data.find(keyword) + len(keyword) + 2  # +2 to skip ": "
            end_index = data.find(',', start_index)
            if end_index == -1:
                end_index = data.find('}', start_index)
            value = data[start_index:end_index].strip('"')
            return f"{keyword}: {value}"
    return None
def capture(interface):# capture http2 packet
    cap = pyshark.LiveCapture(interface=interface, use_json=False, 
                              override_prefs={'tls.keylog_file': 'C:\\temp\\ssl.keys'})
    for packet in cap.sniff_continuously():
     try:
       if 'http2' in packet:
            http2_layer = packet.http2
            for field in http2_layer.field_names:
                if field == 'data_data':
                    json_object = http2_layer.data_data
                    value = json_object.replace(':','')
                    words=bytes.fromhex(value).decode('utf-8',errors='ignore')
                    c=analyze(words)
                    print(c)
     except ValueError:
         continue

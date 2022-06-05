import frida, sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

jscode = open('test.js','r').read()

process = frida.get_usb_device().attach('SKI+')
script = process.create_script(jscode)
script.on('message', on_message)

script.load()
sys.stdin.read()
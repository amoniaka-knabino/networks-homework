from flask import *

from requests import post, get
import os
import re
import urllib
from zipfile import ZipFile

app = Flask(__name__)

client_id = 7469406
secure_key = "sPlgKVe24TM6Jr1KgvIn"
access_code = None
access_token = None
domain = 'localhost'
port = 5050
redirect_uri = f"http://{domain}:{port}/code"
get_wallpost_id = re.compile(r"wall([0-9_\-]*)")


def quire_token_authcode():
    query = f"https://oauth.vk.com/authorize?client_id={client_id}&display=page&redirect_uri={redirect_uri}&scope=wall&response_type=code&v=5.103"
    return redirect(query)


@app.route('/code', methods=['GET'])
def get_token():
    global access_code
    code = request.args.get('code')
    query = f"https://oauth.vk.com/access_token?client_id={client_id}&client_secret={secure_key}&redirect_uri={redirect_uri}&code={code}"
    r = get(query)
    r = r.json()
    _json_token = r
    global access_token
    access_token = r["access_token"]
    return redirect('/')


@app.route('/')
def main():
    if access_token is None:
        return quire_token_authcode()
    else:
        return render_template("index.html")


@app.route('/', methods=['POST'])
def get_photos_from_wallpost():
    link = request.form['link']
    post_id = get_wallpost_id.findall(link)[0]
    query = f"https://api.vk.com/method/wall.getById?posts={post_id}&access_token={access_token}&v=5.103"
    r = get(query)
    to_download = []
    for x in r.json()["response"]:
        if "attachments" not in x:
            continue
        for attachment in x["attachments"]:
            if "photo" in attachment:
                photo_link = find_max_size_link(attachment["photo"])
                to_download.append(photo_link)
    download_zip(to_download)
    return send_from_directory('.', 'images.zip')


def download_zip(to_download):
    zipObj = ZipFile('images.zip', 'w')
    for i in range(len(to_download)):
        filename = f'images/{i}.jpg'
        response = urllib.request.urlopen(to_download[i])
        data = response.read()
        with open(filename, 'wb+') as f:
            f.write(data)
        zipObj.write(filename)
        os.remove(filename)
    zipObj.close()


def find_max_size_link(dic):
    return dic["sizes"][-1]["url"]


if __name__ == '__main__':
    app.run(debug=True, port=port)

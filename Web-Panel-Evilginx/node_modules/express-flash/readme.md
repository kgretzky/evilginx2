# Express Flash

  Flash Messages for your Express Application

  [![Build Status](https://secure.travis-ci.org/RGBboy/express-flash.png)](http://travis-ci.org/RGBboy/express-flash)

  Flash is an extension of `connect-flash` with the ability to define a flash message
  and render it without redirecting the request.

## Installation

  Works with Express 3.x.x

    npm install git://github.com/RGBboy/express-flash.git


## Usage

  Set it up the same way you would `connect-flash`:

``` javascript
  var flash = require('express-flash'),
      express = require('express'),
      app = express();

  app.use(express.cookieParser('keyboard cat'));
  app.use(express.session({ cookie: { maxAge: 60000 }}));
  app.use(flash());
```

Use `req.flash()` in your middleware

``` javascript
  app.get('/', function (req, res) {
    req.flash('info', 'Welcome');
    res.render('index', {
      title: 'Home'
    })
  });
  app.get('/addFlash', function (req, res) {
    req.flash('info', 'Flash Message Added');
    res.redirect('/');
  });
```

Access the messages in your views via `locals.messages` (.jade in this case):

``` jade
  - if (messages.info)
    .message.info
      span= messages.info
```

## Requires

  * cookieParser
  * session

## License 

(The MIT License)

Copyright (c) 2012 RGBboy &lt;me@rgbboy.com&gt;

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
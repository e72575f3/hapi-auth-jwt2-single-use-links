var Hapi = require('hapi'); // https://github.com/nelsonic/learn-hapi
var hapiAuthJWT = require('hapi-auth-jwt2'); // http://git.io/vT5dZ
var JWT = require('jsonwebtoken'); // used to sign our content
var port = process.env.PORT; // allow port to be set
var aguid = require('aguid'); // https://github.com/ideaq/aguid
var url = require('url'); // node core!
var redisClient = require('redis-connection')(); // instantiate redis-connection
var Boom = require('boom');

var options = {
    transport: {
        service: 'Gmail',
        auth: {
            user: process.env.JWT_EMAIL,
            pass: process.env.JWT_EMAIL_PW
        }
    }
};

var hapiMailer = {
    register: require('hapi-mailer'),
    options: options
};



redisClient.set('redis', 'working');
redisClient.get('redis', function(rediserror, reply) {
    /* istanbul ignore if */
    if (rediserror) {
        console.log(rediserror);
    }
    console.log('redis is ' + reply.toString()); // confirm we can access redis
});

// bring your own validation function
var validate = function(decoded, request, callback) {
    console.log(' - - - - - - - DECODED token:');
    console.log(decoded);
    // do your checks to see if the session is valid
    redisClient.get(decoded.id, function(rediserror, reply) {
        /* istanbul ignore if */
        if (rediserror) {
            console.log(rediserror);
        }
        console.log(' - - - - - - - REDIS reply - - - - - - - ', reply);
        var session;
        if (reply) {
            session = JSON.parse(reply);
        } else { // unable to find session in redis ... reply is null
            return callback(rediserror, false);
        }

        if (session.valid === true) {
            return callback(rediserror, true);
        } else {
            return callback(rediserror, false);
        }
    });
};

var server = new Hapi.Server();
server.connection({
    port: port
});

server.register([hapiMailer, hapiAuthJWT], function(err) {
    if (err) {
        console.log(err);
    }
    // see: http://hapijs.com/api#serverauthschemename-scheme
    server.auth.strategy('jwt', 'jwt', true, {
        key: process.env.JWT_SECRET,
        validateFunc: validate,
        verifyOptions: {
            ignoreExpiration: true
        }
    });

    server.route([{
        method: 'GET',
        path: '/',
        config: {
            auth: false
        },
        handler: function(request, reply) {
            reply({
                text: 'Token not required'
            });
        }
    }, {
        method: ['GET', 'POST'],
        path: '/restricted',
        config: {
            auth: 'jwt'
        },
        handler: function(request, reply) {
            reply({
                    text: 'You used a Token!'
                })
                .header('Authorization', request.headers.authorization);
        }
    }, {
        method: ['GET'],
        path: '/access/{accessLink}',
        config: {
            auth: false
        },
        handler: function(request, reply) {
            var decoded;
            try {
                decoded = JWT.decode(request.params.accessLink,
                    process.env.JWT_SECRET);
                // This assignment is required to trigger the catch block if the jwt is not valid
                var accessID = decoded.id;
            } catch (e) {
                return reply(Boom.unauthorized('Invalid token format', 'Token'));
            }
            var accessLink;
            redisClient.get(accessID, function(rediserror, redisreply) {
                /* istanbul ignore if */
                if (rediserror) {
                    console.log(rediserror);
                }
                accessLink = JSON.parse(redisreply);
                console.log(' - - - - - - accessLink - - - - - - - -');
                console.log(accessLink);
                // If access link is visited for the first time and is valid, create a session and set Authorization header
                if (accessLink.valid === true) {
                    var session = {
                        valid: true, // this will be set to false when the person logs out
                        id: aguid(), // a random session id
                        exp: new Date().getTime() + 30 * 60 * 1000 // expires in 30 minutes time
                    };
                    // create the session in Redis
                    redisClient.set(session.id, JSON.stringify(session));
                    // sign the session as a JWT
                    var token = JWT.sign(session, process.env.JWT_SECRET); // synchronous
                    console.log(token);

                    reply({
                            text: 'Check Auth Header for your Token'
                        })
                        .header('Authorization', token);
                } else {
                    reply({
                        text: 'Your access link is not valid.'
                    });
                }
                // Now that the accessLink was used, retire it
                accessLink.valid = false;
                accessLink.used = new Date().getTime();
                // create the accessLink in Redis
                redisClient.set(accessLink.id, JSON.stringify(accessLink));
            });
        }
    }, {
        method: ['POST'],
        path: '/access',
        config: {
            auth: false
        },
        handler: function(request, reply) {
            console.log(request.payload.email);
            var accessLink = {
                valid: true, // this will be set to false once the link is visited
                id: aguid(),
                exp: new Date().getTime() + 30 * 60 * 1000 // expires in 30 minutes time
            };
            // create the accessLink in Redis
            redisClient.set(accessLink.id, JSON.stringify(accessLink));
            // sign the accessLink as a JWT
            var token = JWT.sign(accessLink, process.env.JWT_SECRET); // synchronous
            console.log(token);
            var link = 'http://127.0.0.1:' + port + '/access/' + token;
            var data = {
                from: options.transport.auth.user,
                to: request.payload.email,
                subject: 'Your access link',
                text: 'This is a single use link, click it to get access: ' + link
            };
            var Mailer = request.server.plugins.mailer;
            Mailer.sendMail(data, function(err, info) {
                if (err) {
                    throw err;
                }
            });
            // Remove link reply in a production system
            reply({
                text: 'Your single use link is:',
                link: link
            });
        }
    }, {
        method: ['GET', 'POST'],
        path: '/logout',
        config: {
            auth: 'jwt'
        },
        handler: function(request, reply) {
            // implement your own login/auth function here
            var decoded = JWT.decode(request.headers.authorization,
                process.env.JWT_SECRET);
            var session;
            redisClient.get(decoded.id, function(rediserror, redisreply) {
                /* istanbul ignore if */
                if (rediserror) {
                    console.log(rediserror);
                }
                session = JSON.parse(redisreply);
                console.log(' - - - - - - SESSION - - - - - - - -');
                console.log(session);
                // update the session to no longer valid:
                session.valid = false;
                session.ended = new Date().getTime();
                // create the session in Redis
                redisClient.set(session.id, JSON.stringify(session));

                reply({
                    text: 'Check Auth Header for your Token'
                });
            });
        }
    }]);
});


server.start(function() {
    console.log('Now Visit: http://127.0.0.1:' + port);
}); // uncomment this to run the server directly

module.exports = server;

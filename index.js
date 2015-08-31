'use strict';

var jsrsasign = require('jsrsasign');
var fs = require('fs');
var path = require('path');
var Handlebars = require('handlebars');
var uuid = require('uuid');

var templates = {
    imap: Handlebars.compile(fs.readFileSync(path.join(__dirname, 'templates', 'imap.plist'), 'utf-8')),
    carddav: Handlebars.compile(fs.readFileSync(path.join(__dirname, 'templates', 'carddav.plist'), 'utf-8'))
};

module.exports = {
    sign: function(value, options, callback) {
        options = options || {};

        var pem;
        var der;
        var params = {

            content: {
                // the signed content needs to be a normal unicode string
                str: (value || '').toString('utf-8')
            },

            // join ca certs with signer cert into single array and ensure the values are strings, not Buffer object
            certs: [].concat(options.ca || []).concat(options.cert || []).map(function(cert) {
                return (cert || '').toString();
            }),

            signerInfos: [{

                // sha256, sha512, sha384, sha224, sha1, md5, ripemd160
                hashAlg: options.hashAlg || 'sha256',

                // If signingTime is true, add SigingTime signed attribute
                sAttr: options.signingTime ? {
                    SigningTime: {}
                } : {},

                signerCert: (options.cert || '').toString(),
                signerPrvKey: (options.key || '').toString(),

                // SHA256withRSA, SHA512withRSA, SHA384withRSA, SHA224withRSA, SHA1withRSA,MD5withRSA
                // RIPEMD160withRSA, SHA256withECDSA, SHA512withECDSA, SHA384withECDSA, SHA224withECDSA, SHA1withECDSA
                // SHA256withSA, SHA512withSA, SHA384withSA, SHA224withSA, SHA1withDSA
                sigAlg: options.sigAlg || 'SHA256withRSA'
            }]
        };

        try {
            pem = jsrsasign.asn1.cms.CMSUtil.newSignedData(params).getPEM();
            der = new Buffer(jsrsasign.KEYUTIL.getHexFromPEM(pem, 'CMS'), 'hex');
        } catch (E) {
            return setImmediate(function() {
                callback(E);
            });
        }

        return setImmediate(function() {
            callback(null, der);
        });
    },

    getEmailConfig: function(options, callback) {
        var imap = options.imap || {};
        var smtp = options.smtp || {};

        var data = {
            emailAddress: options.emailAddress || 'admin@localhost',

            organization: options.organization || false,
            identifier: options.identifier || 'com.kreata.anonymous',

            displayName: options.displayName || 'Mail Account',
            displayDescription: options.displayDescription,

            accountName: options.accountName || 'IMAP Account',
            accountDescription: options.accountDescription || false,

            imap: {
                hostname: imap.hostname || 'localhost',
                port: imap.port || (imap.secure ? 993 : 143),
                secure: imap.hasOwnProperty('secure') ? !!imap.secure : imap.port === 993,
                username: imap.username || options.emailAddress || 'anonymous',
                password: imap.password || ''
            },

            smtp: {
                hostname: smtp.hostname || 'localhost',
                port: smtp.port || (smtp.secure ? 465 : 587),
                secure: smtp.hasOwnProperty('secure') ? !!smtp.secure : smtp.port === 465,
                username: smtp.username || false,
                password: smtp.password || false
            },

            contentUuid: options.contentUuid || uuid.v4(),
            plistUuid: options.plistUuid || uuid.v4()
        };

        if(callback) {
            callback(null, templates.imap(data));
            return;
        }

        return templates.imap(data);
    },

    getSignedEmailConfig: function(options, callback) {
        options = options || {};

        var plist;

        try {
            plist = module.exports.getEmailConfig(options);
        } catch (E) {
            return callback(E);
        }

        return module.exports.sign(plist, options.keys, callback);
    },

    getCardDAVConfig: function(options, callback) {
        var dav = options.dav || {};

        var data = {
            emailAddress: options.emailAddress || 'admin@localhost',

            organization: options.organization || false,
            identifier: options.identifier || 'com.kreata.anonymous',

            displayName: options.displayName || 'Mail Account',
            displayDescription: options.displayDescription,

            accountName: options.accountName || 'CardDAV Account',
            accountDescription: options.accountDescription || false,

            dav: {
                hostname: dav.hostname || 'localhost',
                port: dav.port || (dav.secure ? 443 : 80),
                principalurl: dav.principalurl || '',
                secure: dav.hasOwnProperty('secure') ? !!dav.secure : dav.port === 80,
                username: dav.username || options.emailAddress || 'anonymous',
                password: dav.password || ''
            },

            contentUuid: options.contentUuid || uuid.v4(),
            plistUuid: options.plistUuid || uuid.v4()
        };

        if(callback) {
            callback(null, templates.carddav(data));
            return;
        }

        return templates.carddav(data);
    },

    getSignedCardDAVConfig: function(options, callback) {
        options = options || {};

        var plist;

        try {
            plist = module.exports.getCardDAVConfig(options);
        } catch (E) {
            return callback(E);
        }

        return module.exports.sign(plist, options.keys, callback);
    }
};

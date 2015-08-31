'use strict';

var mobileconfig = require('../index');
var chai = require('chai');
var expect = chai.expect;
var fs = require('fs');
var plist = require('plist');

chai.Assertion.includeStack = true;

describe('mobileconfig unit tests', function() {

    describe('#sign', function() {

        it('should sign value', function(done) {

            var value = 'Hello ŠŽ 👻';
            var options = {
                key: fs.readFileSync(__dirname + '/fixtures/key.pem'),
                cert: fs.readFileSync(__dirname + '/fixtures/cert.pem'),
                hashAlg: 'sha256',
                sigAlg: 'SHA256withRSA',
                signingTime: false
            };

            mobileconfig.sign(value, options, function(err, data) {
                expect(err).to.not.exist;
                expect(data.toString('binary')).to.equal(fs.readFileSync(__dirname + '/fixtures/signed-string.der', 'binary'));
                done();
            });

        });

        it('should return an error', function(done) {

            var value = 'Hello ŠŽ 👻';
            var options = {
                key: fs.readFileSync(__dirname + '/fixtures/key.pem'),
                cert: fs.readFileSync(__dirname + '/fixtures/key.pem'),
                hashAlg: 'sha256',
                sigAlg: 'SHA256withRSA',
                signingTime: false
            };

            mobileconfig.sign(value, options, function(err, data) {
                expect(err).to.exist;
                expect(data).to.not.exist;
                done();
            });

        });

    });

    describe('#getEmailConfig', function() {
        it('should generate valid plist', function() {
            var options = {
                emailAddress: 'my-email-address@gmail.com',

                organization: 'My Company',
                identifier: 'com.my.company',

                displayName: 'My Gmail Account',
                displayDescription: 'Install this profile to auto configure your Gmail account',

                accountName: 'IMAP Config',
                accountDescription: 'Configure your Gmail account',

                imap: {
                    hostname: 'imap.gmail.com',
                    port: 993,
                    secure: true,
                    username: 'my-email-address@gmail.com',
                    password: 'mypass'
                },

                smtp: {
                    hostname: 'smtp.gmail.com',
                    port: 587,
                    secure: false,
                    username: 'my-email-address@gmail.com',
                    password: false // use the same password as for IMAP
                },

                contentUuid: 'abcdef',
                plistUuid: 'ghijklmn'
            };

            var emailConfig = plist.parse(mobileconfig.getEmailConfig(options));

            expect(emailConfig).to.deep.equal({
                PayloadContent: [{
                    EmailAccountDescription: 'Configure your Gmail account',
                    EmailAccountType: 'EmailTypeIMAP',
                    EmailAddress: 'my-email-address@gmail.com',
                    IncomingMailServerAuthentication: 'EmailAuthPassword',
                    IncomingMailServerHostName: 'imap.gmail.com',
                    IncomingMailServerPortNumber: 993,
                    IncomingMailServerUseSSL: true,
                    IncomingMailServerUsername: 'my-email-address@gmail.com',
                    IncomingPassword: 'mypass',
                    OutgoingMailServerAuthentication: 'EmailAuthPassword',
                    OutgoingMailServerHostName: 'smtp.gmail.com',
                    OutgoingMailServerPortNumber: 587,
                    OutgoingMailServerUseSSL: false,
                    OutgoingMailServerUsername: 'my-email-address@gmail.com',
                    OutgoingPasswordSameAsIncomingPassword: true,
                    PayloadDescription: 'Configures email account.',
                    PayloadDisplayName: 'IMAP Config',
                    PayloadIdentifier: 'com.my.company',
                    PayloadOrganization: 'My Company',
                    PayloadType: 'com.apple.mail.managed',
                    PayloadUUID: 'abcdef',
                    PayloadVersion: 1,
                    PreventAppSheet: false,
                    PreventMove: false,
                    SMIMEEnabled: false
                }],
                PayloadDescription: 'Install this profile to auto configure your Gmail account',
                PayloadDisplayName: 'My Gmail Account',
                PayloadIdentifier: 'com.my.company',
                PayloadOrganization: 'My Company',
                PayloadRemovalDisallowed: false,
                PayloadType: 'Configuration',
                PayloadUUID: 'ghijklmn',
                PayloadVersion: 1
            });
        });
    });

    describe('#getSignedEmailConfig', function() {
        it('should not return an error', function(done) {
            var options = {
                emailAddress: 'my-email-address@gmail.com',

                organization: 'My Company',
                identifier: 'com.my.company',

                displayName: 'My Gmail Account',
                displayDescription: 'Install this profile to auto configure your Gmail account',

                accountName: 'IMAP Config',
                accountDescription: 'Configure your Gmail account',

                imap: {
                    hostname: 'imap.gmail.com',
                    port: 993,
                    secure: true,
                    username: 'my-email-address@gmail.com',
                    password: 'mypass'
                },

                smtp: {
                    hostname: 'smtp.gmail.com',
                    port: 587,
                    secure: false,
                    username: 'my-email-address@gmail.com',
                    password: false // use the same password as for IMAP
                },

                contentUuid: 'abcdef',
                plistUuid: 'ghijklmn',

                keys: {
                    key: fs.readFileSync(__dirname + '/fixtures/key.pem'),
                    cert: fs.readFileSync(__dirname + '/fixtures/cert.pem'),
                    hashAlg: 'sha256',
                    sigAlg: 'SHA256withRSA',
                    signingTime: false
                }
            };

            mobileconfig.getSignedEmailConfig(options, function(err, data) {
                expect(err).to.not.exist;
                expect(data).to.exist;

                done();
            });
        });
    });

    describe('#getCardDAVConfig', function() {
        it('should generate valid plist', function() {
            var options = {
                organization: 'My Company',
                identifier: 'com.my.company',

                displayName: 'My Contacts',
                displayDescription: 'Install this profile to auto configure your contacts',

                accountName: 'CardDAV Config',
                accountDescription: 'Configure your contact list',

                dav: {
                    hostname: 'http://localhost:8080',
                    port: 8080,
                    secure: false,
                    principalurl: 'http://localhost:8080/dav/username',
                    username: 'username@gmail.com',
                    password: 'mypass'
                },

                contentUuid: 'abcdef',
                plistUuid: 'ghijklmn'
            };

            var emailConfig = plist.parse(mobileconfig.getCardDAVConfig(options));

            expect(emailConfig).to.deep.equal({
                PayloadContent: [{
                    CardDAVAccountDescription: 'Configure your contact list',
                    CardDAVPrincipalURL: 'http://localhost:8080/dav/username',
                    CardDAVHostName: 'http://localhost:8080',
                    CardDAVPort: 8080,
                    CardDAVUseSSL: false,
                    CardDAVUsername: 'username@gmail.com',
                    CardDAVPassword: 'mypass',
                    PayloadDescription: 'username@gmail.com contacts',
                    PayloadDisplayName: 'username@gmail.com contacts',
                    PayloadIdentifier: 'com.my.company',
                    PayloadOrganization: 'My Company',
                    PayloadType: 'com.apple.carddav.account',
                    PayloadUUID: 'abcdef',
                    PayloadVersion: 1
                }],
                PayloadDescription: 'Install this profile to auto configure your contacts',
                PayloadDisplayName: 'My Contacts',
                PayloadIdentifier: 'com.my.company',
                PayloadOrganization: 'My Company',
                PayloadRemovalDisallowed: false,
                PayloadType: 'Configuration',
                PayloadUUID: 'ghijklmn',
                PayloadVersion: 1
            });
        });
    });

    describe('#getSignedEmailConfig', function() {
        it('should not return an error', function(done) {
            var options = {
                emailAddress: 'my-email-address@gmail.com',

                organization: 'My Company',
                identifier: 'com.my.company',

                displayName: 'My Gmail Account',
                displayDescription: 'Install this profile to auto configure your Gmail account',

                accountName: 'IMAP Config',
                accountDescription: 'Configure your Gmail account',

                imap: {
                    hostname: 'imap.gmail.com',
                    port: 993,
                    secure: true,
                    username: 'my-email-address@gmail.com',
                    password: 'mypass'
                },

                smtp: {
                    hostname: 'smtp.gmail.com',
                    port: 587,
                    secure: false,
                    username: 'my-email-address@gmail.com',
                    password: false // use the same password as for IMAP
                },

                contentUuid: 'abcdef',
                plistUuid: 'ghijklmn',

                keys: {
                    key: fs.readFileSync(__dirname + '/fixtures/key.pem'),
                    cert: fs.readFileSync(__dirname + '/fixtures/cert.pem'),
                    hashAlg: 'sha256',
                    sigAlg: 'SHA256withRSA',
                    signingTime: false
                }
            };

            mobileconfig.getSignedEmailConfig(options, function(err, data) {
                expect(err).to.not.exist;
                expect(data).to.exist;

                done();
            });
        });
    });

});
'use strict';

angular.module('wardenOAuth')
    .service('JwtTokenService', function($http, StorageService, jwtHelper) {


        /**
         * Parses the userName out of the given subject string.
         *
         * @param subject expected format: 'domain/userName'
         * @returns {*} userName or subject if no / present
         */
        function parseUserName(subject) {
            var result = subject;

            var delimiterIndex = subject.lastIndexOf("/");

            if(delimiterIndex >= 0 && delimiterIndex !== subject.length-1){
                result = subject.substring(delimiterIndex + 1, subject.length);
            }

            return result;
        }

        /**
         * Parse an identity object from the given jwt token
         * @param jwt
         * @returns {*}
         */
        this.parseIdentity = function (jwt) {

            var claims = jwtHelper.decodeToken(jwt);
            if(claims){

                var identity = {
                    access_token: jwt,
                    expires_at: jwtHelper.getTokenExpirationDate(jwt),
                    userLogin: parseUserName(claims.sub),
                    subject: claims.sub,
                    name: claims.name,
                    realm: claims.aud,
                    roles: claims.roles,
                    language: claims.lang,

                    isValid: function () {

                        // jwtHelper.isTokenExpired(jwt)

                        if (this.expires_at === null) {
                            return false;
                        }
                        // Token NOT expired?
                        return (this.expires_at.valueOf() > (new Date().valueOf()));
                    }
                };

                return identity;

            }else{
                throw "JWT token has unexpected format, cant parse it!";
            }
        };

        this.deleteToken = function() {
            console.log('Deleting local JWT token...');
            this.setToken(null);
        };

        /**
         * Sets a token into the local storage
         * @param token
         */
        this.setToken = function(token) {
            StorageService.save('token', token);
        };

        /**
         * Gets the current access token -
         * either from local storage or from url query param
         */
        this.getToken = function() {
            return StorageService.get('token');
        };

    });





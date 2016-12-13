'use strict';

angular.module('wardenOAuth')

    .factory('authInterceptor', function ($rootScope, $q, $injector) {
        return {
            /**
             * Add authorization token to HTTP Header on each request
             */
            request: function (config) {

                config.headers = config.headers || {};

                try {
                    var Principal = $injector.get('Principal');

                    if(Principal.isAuthenticated()){
                        var identity = Principal.getIdentity();
                        if(identity.access_token){
                            var authHeader = 'Bearer ' + identity.access_token;
                            //console.log("Injecting bearer token: " + authHeader);
                            config.headers.Authorization = authHeader;
                        }else{
                            console.log("The current principal identity does not have an access token - cant add bearer token to header!");
                        }
                    }else{
                        console.log("Can not add bearer token - Not authenticated yet.");
                    }
                }catch(err){
                    console.log("Something went wrong in authInterceptor! " + JSON.stringify(err));
                }

                return config;
            }
        };
    })

    .factory('authExpiredInterceptor', function ($rootScope, $q, $injector) {
        return {
            responseError: function (response) {
                // The token has expired or the user attempts to access resources he is not allowed to
                if (response.status === 401) {
                    console.log("Got an 401 Error (Not authorized) from the backend.");
                    var Auth = $injector.get('Auth');
                    Auth.permissionDenied();
                }
                return $q.reject(response);
            }
        };
    });
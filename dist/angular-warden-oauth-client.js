(function() {


'use strict';

angular.module('wardenOAuth',
    [
        'angular-jwt',
        'webstorageLight',
        'ui.router'
    ]);

angular.module('wardenOAuth')

    .run(["$rootScope", "$location", "$window", "$http", "$state", "Auth", function ($rootScope, $location, $window, $http, $state,
                   Auth) {

    }])

    .config(["$httpProvider", function ($httpProvider) {
        $httpProvider.interceptors.push('authInterceptor');
        $httpProvider.interceptors.push('authExpiredInterceptor');
    }])
;
'use strict';

angular.module('wardenOAuth')

    .provider('Auth', function AuthProvider() {

        var _config = {

            clientId : "myApp",
            loginUrl : "/warden/warden-ui/index.html#/realms/master/oauth/login",
            accessDeniedHandler : function () {
                var $state = angular.injector().get('$state');
                $state.go("accessdenied");
            },
            defaultRedirectState : "home"
        };

        this.config = function(config) {
            _config = config;
        };

        this.$get = ["$rootScope", "$state", "$window", "Principal", "JwtTokenService", "UrlLocationService",
            function($rootScope, $state, $window, Principal, JwtTokenService, UrlLocationService) {

            // Private fields
            var _desiredState = null;
            var _desiredStateParams = null;

            var Auth = {


                permissionDenied : function () {
                    if (Principal.isAuthenticated()) {

                        console.log("User is signed in but not authorized for desired state!");

                        // user is signed in but not authorized for desired state
                        _config.accessDeniedHandler();
                    }else {
                        console.log("User is not authenticated - going to Login!");
                        this.redirectToLogin();
                    }
                },

                redirectToLogin : function () {
                    var loginUri = this.getLoginUrl();
                    console.log("Redirecting to OAuth-Login '" + loginUri + "' ...");
                    this.redirectTo(loginUri);
                },

                redirectToLogout : function () {
                    var logoutUri = this.getLogoutUrl();
                    this.redirectTo(logoutUri);
                },

                redirectTo : function (url) {
                    $window.location.href = url;
                },

                getLogoutUrl : function () {
                    return this.getLoginUrl() + "&action=logout";
                },

                /**
                 * Returns the OAuth login URL
                 * @returns {*|string}
                 */
                getLoginUrl : function () {

                    var redirectUri;

                    if(_desiredState){
                        redirectUri = $state.href(_desiredState.name, _desiredStateParams, {absolute: true});
                    }else{
                        redirectUri = $state.href(_config.defaultRedirectState, {}, {absolute: true});
                    }

                    return this.getOAuthLoginUrl(_config.clientId, redirectUri);
                },

                /**
                 * Gets the OAuth login URL
                 * @param client_id
                 * @param redirect_uri
                 * @returns {string}
                 */
                getOAuthLoginUrl : function (client_id, redirect_uri) {
                    var loginUri = _config.loginUrl + "?response_type=token&client_id="+encodeURIComponent(client_id)+"&redirect_uri="+encodeURIComponent(redirect_uri);
                    return loginUri;
                },


                /**
                 * Returns the JWT token from the URL if available.
                 * @returns {string} Returns a JWT token string if present.
                 */
                fetchUrlToken : function () {

                    // Token from URL
                    console.log("Checking if a query url param is set with a token ...");
                    var queryParams = UrlLocationService.parseQueryParams();
                    var token = queryParams['token'];

                    // Check if valid token

                    if(angular.isString(token) && token.length > 10){
                        console.log("Found JWT in URL: " + token);
                        UrlLocationService.deleteQueryParam('token');
                        return token;
                    }else{
                        return null;
                    }
                },


                /**
                 * Tries to authenticate by fetching the token from
                 * the local storage or the url query param ?token/jwt
                 */
                authenticate: function(){

                    console.log("Trying to authenticate with existing token ...");

                    var token = this.fetchUrlToken();
                    if(token){
                        console.log("Persisting token from URL ...");
                        JwtTokenService.setToken(token);
                    }

                    token = JwtTokenService.getToken();
                    if (token) {
                        var identity = JwtTokenService.parseIdentity(token);

                        if(identity.isValid()){

                            // Success

                            Principal.authenticate(identity);

                            console.log("Principal authenticated with: " + JSON.stringify(identity));

                            if (identity.langKey) {
                                // After the login the language will be changed to
                                // the language selected by the user during his registration
                                // TODO $translate.use(identity.langKey);
                            }
                        }else{
                            Principal.authenticate(null);
                            console.error("The parsed identity was not valid (token probably expired)!");
                        }
                    }else{
                        Principal.authenticate(null);
                        console.log("No token found, cant authenticate.");
                    }

                },

                /**
                 * Performs a logout of the current user.
                 *
                 * @param {boolean} global Perform a global logout?
                 */
                logout: function (global) {

                    console.log("Logging out...");
                    JwtTokenService.deleteToken();
                    Principal.authenticate(null);

                    if(global){
                      // Global logout
                      this.redirectToLogout();
                    }
                },

                /**
                 * Checks if the current user has permission to visit the given state
                 * @param state The state to check
                 * @returns {boolean}
                 */
                hasPermission : function(state) {
                    if (state.data &&
                        state.data.roles &&
                        state.data.roles.length > 0 &&
                        !Principal.isInAnyRole(state.data.roles)) {

                        // User has not the required roles
                        console.log("User has not the required web-ui roles: "+ JSON.stringify(state.data.roles) +"! Current User: " + JSON.stringify(Principal));
                        return false;
                    }
                    return true;
                }
            };

            // Install a $stateChangeStart event listener
            $rootScope.$on('$stateChangeStart', function (event, toState, toStateParams) {

                // console.log("auth.service.js - $stateChangeStart");
                _desiredState = toState;
                _desiredStateParams = toStateParams;

                Auth.authenticate();

                if(!Auth.hasPermission(toState)){

                    console.log("User lacks privilege for requested state '"+toState.name+"'. Handling ...");

                    event.preventDefault();
                    Auth.permissionDenied();

                }else{
                    console.log("Permission granted for state '" + toState.name + "'")
                }
            });

            return Auth;

        }]; // end $get()


    });

'use strict';

angular.module('wardenOAuth')

    .factory('authInterceptor', ["$rootScope", "$q", "$injector", function ($rootScope, $q, $injector) {
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
    }])

    .factory('authExpiredInterceptor', ["$rootScope", "$q", "$injector", function ($rootScope, $q, $injector) {
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
    }]);
'use strict';

angular.module('wardenOAuth')
    .service('JwtTokenService', ["$http", "StorageService", "jwtHelper", function($http, StorageService, jwtHelper) {


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
                    userLogin: claims.sub,
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

    }]);





'use strict';

angular.module('wardenOAuth')

    /**
     * Represents the currently logged in user
     */
    .factory('Principal', function Principal() {
        var _identity = null;

        return {

            getIdentity: function(){
                return _identity;
            },

            isAuthenticated: function () {
                if(!!_identity){
                    // We have a identity - check if its not expired yet!
                    return _identity.isValid();
                }
                return false;
            },

            isAnonymous: function () {
                return !this.isAuthenticated();
            },

            isInRole: function (role) {
                if (!this.isAuthenticated() || !_identity.roles) {
                    return false;
                }

                return _identity.roles.indexOf(role) !== -1;
            },

            isInAnyRole: function (roles) {
                if (!this.isAuthenticated() || !_identity.roles) {
                    return false;
                }

                for (var i = 0; i < roles.length; i++) {
                    if (this.isInRole(roles[i])) {
                        return true;
                    }
                }

                return false;
            },

            /**
             * Set the current identity object
             * @param identity
             */
            authenticate: function (identity) {
                _identity = identity;
            }
        };
    });


/*jshint bitwise: false*/
'use strict';

angular.module('wardenOAuth')

    .factory('UrlLocationService', ["$location", function ($location) {
        return {

            parseQueryParams: function () {
                return $location.search();
            },

            deleteQueryParam: function (key) {
                console.log("Attempting to delete query param " + key );
                $location.search(key, null);
            }
        };
    }]);


}());
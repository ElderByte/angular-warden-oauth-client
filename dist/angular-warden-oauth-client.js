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
            loginState : null,
            accessDeniedState : "accessdenied",
            defaultRedirectState : "home",
            stateRoleSecurityEnabled : true
        };

        this.config = function(config) {
            _config = config;
        };

        this.$get = ["$rootScope", "$state", "$window", "$transitions",
                     "Principal", "JwtTokenService", "UrlLocationService",

            function($rootScope, $state, $window, $transitions,
                     Principal, JwtTokenService, UrlLocationService) {

            // Private fields

            var _previousState = null;
            var _previousStateParams = null;
            var _desiredState = null;
            var _desiredStateParams = null;


            var Auth = {

              /**
              * Signs the given URL with the current JWT token so it can be used
              * as a download/remote link.
              *
              * @param The url which should be authorized.
              * @returns {string} The authorized url
              */
              authorizeUrl : function(url){
                if(Principal.isAuthenticated()){
                    var identity = Principal.getIdentity();
                    if(identity.access_token){
                        return UrlLocationService.setQueryParam(url, 'token', identity.access_token);
                    }else{
                        throw "Can not authorize URL with JWT token - The current principal identity does not have an access token.";
                    }
                }else{
                  throw "Can not authorize URL with JWT token - Not authenticated yet.";
                }
              },

              /**
               * Sends the user to the login page.
               * If oAuth, this will redirect to another web-site
               * If local login, it will transition to the login state.
               */
              redirectToLogin : function () {

                  if(_config.loginState){
                    // Custom local login state
                    console.log('Sending user to local login state: ' + _config.loginState);
                    var params = {};
                    if(_desiredState){
                      params = {
                        desiredStateName : _desiredState.name,
                        desiredStateParams : _desiredStateParams
                      }
                    }
                    $state.go(_config.loginState, params);
                    return true;
                  }

                  if(_config.loginUrl){
                    // OAuth
                    var loginUri = this.getLoginUrl();
                    console.log("Redirecting to OAuth-Login '" + loginUri + "' ...");
                    this._redirectTo(loginUri);
                    return true;
                  }

                  return false;
              },


              redirectToLogout : function () {
                  var logoutUri = this.getLogoutUrl();
                  this._redirectTo(logoutUri);
              },

              getLogoutUrl : function () {
                  return this.getLoginUrl() + "&action=logout";
              },

              /**
               * Returns the OAuth login URL
               * @returns {*|string}
               */
              getLoginUrl : function () {

                  var state;
                  var params = {};

                  if(_desiredState){
                      state = _desiredState.name;
                      params = _desiredStateParams;
                  }else{
                      state = _config.defaultRedirectState;
                  }
                  var redirectUri = UrlLocationService.getAbsoluteStateUrl(state, params);
                  return this._getOAuthLoginUrl(_config.clientId, redirectUri);
              },

              /**
               * Login with a JWT token.
               * It must be present or an exception is thrown.
               */
              loginWithJwt : function(jwtToken){

                  if(!jwtToken) throw "You must provide a JWT token in Auth.loginWithJwt(jwt)";

                  JwtTokenService.setToken(jwtToken);
                  var identity = JwtTokenService.parseIdentity(jwtToken);
                  if(identity.isValid()){
                      // Success
                      Principal.authenticate(identity);
                      console.log("Principal authenticated with: " + JSON.stringify(identity));
                      return true;
                  }else{
                      console.error("The parsed identity was not valid (token probably expired)!");
                      this.logout(false);
                      return false;
                  }
              },

              /**
               * Tries to authenticate by fetching the token from
               * the local storage or the url query param ?token/jwt
               */
              authenticate: function(){

                  console.log("Trying to authenticate with existing token ...");

                  var token = this._fetchUrlToken();
                  if(!token){
                      // Maybe we have a token in the local storage we can use
                      token = JwtTokenService.getToken();
                  }

                  if (token) {
                      if(this.loginWithJwt(token)){
                          $rootScope.$broadcast('wardenLoginSuccessEvent');
                      }else {
                          $rootScope.$broadcast('wardenLoginFailureEvent');
                      }
                  }else{
                      Principal.authenticate(null);
                      console.log("No token found, cant authenticate.");
                  }
              },

              /**
               * Performs a logout of the current user.
               *
               * @param {boolean} global Perform a global logout? (on the oauth server?)
               */
              logout: function (global) {

                  console.log("Logging out...");
                  JwtTokenService.deleteToken();
                  Principal.authenticate(null);
                  $rootScope.$broadcast('wardenLogoutEvent');

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

                  if(!_config.stateRoleSecurityEnabled){
                    return true;
                  }

                  if (state.data &&
                      state.data.roles &&
                      state.data.roles.length > 0 &&
                      !Principal.isInAnyRole(state.data.roles)) {

                      // User has not the required roles
                      console.log("User has not the required web-ui roles: "+ JSON.stringify(state.data.roles) +"! Current User: " + JSON.stringify(Principal));
                      return false;
                  }
                  return true;
              },

              permissionDenied : function() {
                  this._permissionDenied(_previousState, _previousStateParams, _desiredState, _desiredStateParams);
              },

              /***************************************************************************
               *                                                                         *
               * Private methods                                                         *
               *                                                                         *
               **************************************************************************/

               /**
                * Invoked when the user tried to navigate a state (desired) he is not allowed to.
                * @param from The origin state
                * @param desired The state he was denied to visit
                */
               _permissionDenied : function (from, fromParams, desired, desiredParams) {
                   if (Principal.isAuthenticated()) {

                       console.log("User is signed in but not authorized for desired state!");

                      if(_config.accessDeniedState){

                        $state.go(_config.accessDeniedState, {
                            desiredState : desired.name,
                            desiredStateParams : desiredParams,
                            redirectBackUrl : UrlLocationService.getAbsoluteStateUrl(from.name, fromParams)
                        });

                      }else {
                        console.log("No access-denied state has been provided!")
                      }
                   }else {
                       console.log("User is not authenticated - going to Login!");
                       this.redirectToLogin();
                   }
               },

              /**
               * Returns the JWT token from the URL if available.
               * @returns {string} Returns a JWT token string if present.
               */
              _fetchUrlToken : function () {

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
               * Gets the OAuth login URL
               * @param client_id
               * @param redirect_uri
               * @returns {string}
               */
              _getOAuthLoginUrl : function (client_id, redirect_uri) {
                  var loginUri = _config.loginUrl + "?response_type=token&client_id="+encodeURIComponent(client_id)+"&redirect_uri="+encodeURIComponent(redirect_uri);
                  return loginUri;
              },

              _redirectTo : function (url) {
                  $window.location.href = url;
              }

            };

            // Authentication hook

            $transitions.onBefore({}, function (trans) {

                // Before we grant to visit a given state, we check if there are role restrictions.
                _desiredState = trans.$to();
                _desiredStateParams = trans.params();
                _previousState = trans.$from();
                _previousStateParams = trans.params('from');

                Auth.authenticate();

                if(!Auth.hasPermission(_desiredState)){
                    console.log("User lacks privilege for requested state '"+_desiredState.name+"'!");
                    Auth.permissionDenied();
                    return false;
                }else{
                    return true; // Permission granted to transition to requested state
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

    .factory('UrlLocationService', ["$location", "$state", function ($location, $state) {
        return {

            /**
            * Updates all query parameters in the given url
            * with the given queryParams map.
            *
            * @param uri The url which should be updated
            * @param queryParams {map} A key-value map interpreted as query key / value
            * @returns {string} Returns the new url with all query parameters.
            */
            updateQueryString : function (uri, queryParams) {
                var keys = Object.keys(queryParams);
                for(var i=0;i<keys.length;i++) {
                    var key = keys[i];
                    var value = queryParams[key];
                    uri = this.setQueryParam(uri, key, value);
                }
                return uri;
            },

            /**
             * Updates the query-param in the given url with the new value.
             * If the url contains a hash-bang (#) part, the query parameter is append after it.
             *
             * @param key The key
             * @param value The new value
             * @param url The url to update
             * @returns {string} Returns the new url with the given query parameter
             */
            setQueryParam : function(url, key, value) {

                var parts = url.split('#');
                var part = parts[parts.length-1]; // Get the last part

                // TODO if the query param already exists, we should update it. (regex-replace)

                var startDelimiter;
                if(part.includes('?')){
                    startDelimiter = '&';
                }else{
                    startDelimiter = '?';
                }

                // Append key=value

                return url + startDelimiter + key + '=' + encodeURIComponent(value);
            },

            /**
            * Returns a map with all query params
            *
            * var params = UrlLocationService.parseQueryParams();
            * var p = params['token'];
            *
            */
            parseQueryParams: function () {
                return $location.search();
            },

            /**
            * Deletes the query param with the given key from the browser address bar.
            * (Works only with params after #-hash-bang)
            *
            * @param key The query parameter key to delete.
            */
            deleteQueryParam: function (key) {
                console.log("Attempting to delete query param " + key );
                $location.search(key, null);
            },

            /**
            * Returns an absolute URL with the given state/params
            *
            * This method is more robust than $state.href(s,p,{absolute : true})
            *
            * @param state The state name
            * @param params The state params map
            */
            getAbsoluteStateUrl : function(state, params) {

              var absUrl = this._absUrlTillHash();
              var stateUrl = $state.href(state, params);
              var angularRoute = this._trimUntilHash(stateUrl);

              return absUrl + "#" + angularRoute;
            },

            // ------------

            /**
            * Returns the current absolute url including the path,
            * but without the hash-bang part.
            *
            * given:  'http://server.any/thing?asdf#/after/the/bang'
            * =>
            * result: 'http://server.any/thing?asdf'
            *
            */
            _absUrlTillHash: function (){
              return window.location.href.split('#',1)[0];
            },

            /**
            * Trims a given url (part) until a hash-bang:
            * given: 'any/thing?asdf#/after/the/bang'
            * =>
            * result: '/after/the/bang'
            */
            _trimUntilHash : function (url){
               var parts = url.split('#',2);
               return parts.length == 1 ? parts[0] : parts[1];
            }

        };
    }]);

}());
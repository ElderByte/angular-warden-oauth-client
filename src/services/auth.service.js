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

                    var state;
                    var params = {};

                    if(_desiredState){
                        state = _desiredState.name;
                        params = _desiredStateParams;
                    }else{
                        state = _config.defaultRedirectState;
                    }
                    var redirectUri = this.getAbsoluteStateUrl(state, params);
                    return this.getOAuthLoginUrl(_config.clientId, redirectUri);
                },


                getAbsoluteStateUrl : function(state, params) {
                  //return $state.href(_desiredState.name, _desiredStateParams, {absolute: true});

                  var absUrl = UrlLocationService.absUrlTillHash();
                  var stateUrl = $state.href(_desiredState.name, _desiredStateParams);
                  var angularRoute = UrlLocationService.trimUntilHash(stateUrl);

                  return absUrl + "#" + angularRoute;
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

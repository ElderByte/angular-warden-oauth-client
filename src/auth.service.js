'use strict';

angular.module('wardenOAuth')

    .provider('Auth', function AuthProvider() {

        var _config = {

            clientId : "myApp",
            loginUrl : "/warden/warden-ui/index.html#/realms/master/oauth/login",
            accessDeniedHandler : function () {
                $state.go("accessdenied");
            }
        };

        this.config = function(config) {
            _config = config;
        };

        this.$get = ["$rootScope", "$state", "$window", "Principal", "JwtTokenService", "UrlLocationService",
            function($rootScope, $state, $window, Principal, JwtTokenService, UrlLocationService) {

            // Private fields
            var _deniedState = null;
            var _deniedStateParams = null;

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
                    $window.location.href = loginUri;
                },


                /**
                 * Returns the OAuth login URL
                 * @returns {*|string}
                 */
                getLoginUrl : function () {

                    var redirectUri;

                    if(_deniedState){
                        redirectUri = $state.href(_deniedState.name, _deniedStateParams, {absolute: true});
                    }else{
                        redirectUri = $state.href('home', {}, {absolute: true});
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
                 * @returns {*}
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

                logout: function () {

                    console.log("Logging out...");
                    JwtTokenService.deleteToken();
                    Principal.authenticate(null);

                    // TODO Redirect to OAuth logout
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

            $rootScope.$on('$stateChangeStart', function (event, toState, toStateParams) {


                console.log("auth.service.js - $stateChangeStart");

                Auth.authenticate();


                if(!Auth.hasPermission(toState)){

                    console.log("User lacks privilege for requested state '"+toState.name+"'. Handling ...");

                    _deniedState = toState;
                    _deniedStateParams = toStateParams;

                    event.preventDefault();
                    Auth.permissionDenied();

                }else{
                    console.log("Permission granted for state '" + toState.name + "'")
                }
            });

            return Auth;

        }]; // end $get()


    });

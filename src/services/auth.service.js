'use strict';

angular.module('wardenOAuth')

    .provider('Auth', function AuthProvider() {

        var _config = {

            clientId : "myApp",
            loginUrl : "/warden/warden-ui/index.html#/realms/master/oauth/login",
            loginState : null,
            accessDeniedHandler : function () {
                var $state = angular.injector().get('$state');
                $state.go("accessdenied");
            },
            defaultRedirectState : "home",
            stateRoleSecurityEnabled : true
        };

        this.config = function(config) {
            _config = config;
        };

        this.$get = ["$state", "$window", "$transitions",
                     "Principal", "JwtTokenService", "UrlLocationService",

            function($state, $window, $transitions,
                     Principal, JwtTokenService, UrlLocationService) {

            // Private fields
            var _desiredState = null;
            var _desiredStateParams = null;

            var Auth = {


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
                  }

                  if(_config.loginUrl){
                    // OAuth
                    var loginUri = this.getLoginUrl();
                    console.log("Redirecting to OAuth-Login '" + loginUri + "' ...");
                    this._redirectTo(loginUri);
                  }
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

                  JwtTokenService.setToken(token);
                  var identity = JwtTokenService.parseIdentity(token);
                  if(identity.isValid()){
                      // Success
                      Principal.authenticate(identity);
                      console.log("Principal authenticated with: " + JSON.stringify(identity));
                  }else{
                      console.error("The parsed identity was not valid (token probably expired)!");
                      this.logout(false);
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
                      this.loginWithJwt(token);
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


              /***************************************************************************
               *                                                                         *
               * Private methods                                                         *
               *                                                                         *
               **************************************************************************/

               _permissionDenied : function () {
                   if (Principal.isAuthenticated()) {

                       console.log("User is signed in but not authorized for desired state!");

                       // user is signed in but not authorized for desired state
                       _config.accessDeniedHandler();
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

                Auth.authenticate();

                if(!Auth.hasPermission(_desiredState)){
                    console.log("User lacks privilege for requested state '"+_desiredState.name+"'!");
                    Auth._permissionDenied();
                    return false;
                }else{
                    return true; // Permission granted to transition to requested state
                }
            });


            return Auth;
        }]; // end $get()


    });

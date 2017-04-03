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

            function($state, $window, $transitions,
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

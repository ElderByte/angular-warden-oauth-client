# angular-warden-oauth-client
Provides an Angular OAuth client for JWT handling. Supports role based security integrated with ui-router.

## Usage

Include the `wardenOAuth` module as a dependency of your Angular App.

* It will automatically register $http injectors which inject the current JWT token to your requests
* It will check the upcoming state required roles with the roles of the currently logged-in user.
* If there is no logged in user, it will redirect you to the OAuth server for login.
* Upon login, the JWT will be parsed and available as Identity object `Principal.getIdentity()`

### Requiring roles for a state

You can specify the required roles for a state by defining a roles array `roles: ['USER']` in the data section of your state:
```javascript
$stateProvider
            .state('positions', {
                parent: 'home',
                url: '/something',
                data: {
                    roles: ['USER'], // Requires the USER role to be present
                },

                templateUrl: 'scripts/app/someting/something.html',
                controller: 'SomethingController'
            });
```

This is obviously only a visual help for your users so that the dont see parts to which they dont have access. To enforce your role based security, you need to validate the roles on your REST API endpoint.

## Configuration

You can configure the OAuth client in your Angular configuration section by injecting the `AuthProvider`.
```javascript
.config(function (AuthProvider) {

	AuthProvider.config({
		clientId : "myApp",
        loginUrl : "https://myOAuthServer.com/oauth/login",
        accessDeniedHandler : function () {
        	var $state = angular.injector().get('$state');
            $state.go("accessdenied");
        },
		defaultRedirectState : "home",
        stateRoleSecurityEnabled : true
	});
	
});
```


**Credits**

[angular-jwt](https://github.com/auth0/angular-jwt)

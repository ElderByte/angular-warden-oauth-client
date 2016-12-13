'use strict';

angular.module('wardenOAuth',
    [
        'angular-jwt',
        'webstorageLight',
        'ui.router'
    ]);

angular.module('wardenOAuth')

    .run(function ($rootScope, $location, $window, $http, $state,
                   Auth) {

    })

    .config(function ($httpProvider) {
        $httpProvider.interceptors.push('authInterceptor');
        $httpProvider.interceptors.push('authExpiredInterceptor');
    })
;
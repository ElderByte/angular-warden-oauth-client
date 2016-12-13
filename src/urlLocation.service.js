/*jshint bitwise: false*/
'use strict';

angular.module('wardenOAuth')

    .factory('UrlLocationService', function ($location) {
        return {

            parseQueryParams: function () {
                return $location.search();
            },

            deleteQueryParam: function (key) {
                console.log("Attempting to delete query param " + key );
                $location.search(key, null);
            }
        };
    });


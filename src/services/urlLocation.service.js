/*jshint bitwise: false*/
'use strict';

angular.module('wardenOAuth')

    .factory('UrlLocationService', function ($location, $state) {
        return {

            parseQueryParams: function () {
                return $location.search();
            },

            deleteQueryParam: function (key) {
                console.log("Attempting to delete query param " + key );
                $location.search(key, null);
            },

            /**
            * Returns an absolute URL with the given state/params
            *
            * This method is more robust than $state.href(s,p,{absolute : true})
            */
            getAbsoluteStateUrl : function(state, params) {

              var absUrl = this._absUrlTillHash();
              var stateUrl = $state.href(state, params);
              var angularRoute = this._trimUntilHash(stateUrl);

              return absUrl + "#" + angularRoute;
            },

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
    });

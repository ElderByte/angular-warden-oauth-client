/*jshint bitwise: false*/
'use strict';

angular.module('wardenOAuth')

    .factory('UrlLocationService', function ($location, $state) {
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
    });

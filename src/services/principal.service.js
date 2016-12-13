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


angular.module("openid.configuration", ['ngRoute'])
    .constant('contextPath', contextPath)
    .constant('restPath', contextPath + "/rest/jira-openid-authentication/1.0")
    .factory('baseUrl', function() {
        return WRM.data.claim('openid.baseUrl');
    })
    .factory('externalUserManagement', function() {
        return WRM.data.claim('openid.externalUserManagement');
    })
    .factory('publicMode', function() {
        return WRM.data.claim('openid.publicMode');
    })
    .factory('creatingUsers', function() {
        return WRM.data.claim('openid.creatingUsers');
    })
    .factory('providerTypes', function() {
        return WRM.data.claim('openid.providerTypes');
    })
    .factory('serviceDesk', function() {
        return WRM.data.claim('openid.servicedesk') === true;
    })
    .factory('sessionTimeout', function() {
        return WRM.data.claim('openid.sessionTimeout');
    })
    .factory('data', function() {
        return WRM.data.claim('openid.data');
    })
    .factory('errorHandler', ['$window', function($window) {
        return {
            handleError: function(data, status) {
                if (status == 401) {
                    $window.location.replace(contextPath + '/login.jsp?permissionViolation=true&os_destination=' + encodeURIComponent($window.location.href));
                }
            }
        }
    }])
    .factory('providers', ['$q', '$http', '$log', 'restPath', function($q, $http, $log, restPath) {
        var providers = [];
        return {
            resetProviders: function() {
                providers = undefined;
            },
            getProviders: function() {
                var deferred = $q.defer();
                if (providers == undefined || !providers.length) {
                    $http.get(restPath + "/providers").success(function(response) {
                        providers = response;
                        deferred.resolve(response);
                    }).error(function(msg, code) {
                        deferred.reject(msg);
                        $log.error(msg, code);
                    });
                } else {
                    deferred.resolve(providers);
                }
                return deferred.promise;
            },
            getProviderById: function(providerId) { return _.find(providers, function(p) { return p.id == providerId; } )}
        }
    }])
    .config(['$routeProvider', 'restPath', function ($routeProvider, restPath) {
        $routeProvider
            .when('/', {
                controller: 'ProvidersCtrl',
                templateUrl: restPath + '/templates/OpenId.Templates.Configuration.providers'
            })
            .when('/edit/:providerId', {
                controller: 'EditProviderCtrl',
                templateUrl: restPath + '/templates/OpenId.Templates.Configuration.editProvider'
            })
            .when('/delete/:providerId', {
                controller: 'DeleteProviderCtrl',
                templateUrl: restPath + '/templates/OpenId.Templates.Configuration.deleteProvider'
            })
            .when('/create', {
                controller: 'CreateProviderCtrl',
                templateUrl: restPath + '/templates/OpenId.Templates.Configuration.createProvider'
            })
            .otherwise({ redirectTo: '/' });
    }])
    .controller('ProvidersCtrl', ['$scope', '$http', 'restPath', 'externalUserManagement',
            'publicMode', 'creatingUsers', 'providers', 'serviceDesk', 'contextPath',
            'sessionTimeout',
            function ($scope, $http, restPath, externalUserManagement, publicMode, creatingUsers, providers, serviceDesk,
                contextPath, sessionTimeout) {
        $scope.isPublicMode = publicMode;
        $scope.isExternalUserManagement = externalUserManagement;
        $scope.isCreatingUsers = creatingUsers;
        $scope.serviceDesk = serviceDesk;
        $scope.contextPath = contextPath;
        $scope.sessionTimeout = sessionTimeout;

        var setProviders = function (data) {
            $scope.providers = data;
            $scope.loaded = true;
            $scope.error = false;
        };

        $scope.creatingUsers = function(create) {
            $http.put(restPath + "/settings", {creatingUsers: create}).success(
                function(response) {
                    $scope.isCreatingUsers = response.creatingUsers;
                }
            );
        };

        $scope.moveProviderUp = function (providerId) {
            $http.post(restPath + "/providers/moveUp/" + providerId, null, {
                headers: {
                    "X-Atlassian-Token": "no-check"
                }
            }).success(setProviders);
        };

        $scope.moveProviderDown = function (providerId) {
            $http.post(restPath + "/providers/moveDown/" + providerId, null, {
                headers: {
                    "X-Atlassian-Token": "no-check"
                }
            }).success(setProviders);
        };

        $scope.enableProvider = function(providerId, enabled) {
            $http.post(restPath + "/providers/" + providerId + "/state", { enabled: enabled }).success(setProviders);
        };

        providers.getProviders().then(setProviders, function (data) {
            $scope.error = true;
        });
    }])
    .controller('CreateProviderCtrl', ['$scope', '$location', '$http', 'providers', 'restPath', 'baseUrl', 'errorHandler', 'providerTypes', 'data',
        function ($scope, $location, $http, providers, restPath, baseUrl, errorHandler, providerTypes, data) {

        $scope.baseUrl = baseUrl;
        $scope.providerTypes = providerTypes;
        $scope.sslMismatch = data.sslMismatch;
        $scope.sslDocumentation = data.sslDocumentation;

        $scope.callbackId = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
            var r = Math.random()*16|0, v = c == 'x' ? r : (r&0x3|0x8);
            return v.toString(16);
        });

        $scope.$watch("providerType", function(newValue, oldValue) {
            $scope.provider.callbackId = newValue.id != 'oauth2' ? newValue.id : $scope.callbackId;
            $scope.provider.name = newValue.defaultName;
            $scope.provider.prompt = _.first($scope.providerType.supportedPrompts);
        });

        $scope.providerType = $scope.providerTypes[0];

        $scope.provider = { extensionNamespace: 'ext1' };
        $scope.provider.callbackId = $scope.callbackId;
        $scope.provider.prompt = _.first($scope.providerType.supportedPrompts);

        $scope.createProvider = function($event) {
            $event.preventDefault();
            $scope.errors = {};
            $scope.errorMessages = [];

            var newProvider = angular.extend({}, $scope.provider, {providerType: $scope.providerType.id});
            $http.post(restPath + '/providers', newProvider).success(function(response) {
                if (response.errorMessages == undefined && response.errors == undefined) {
                    providers.resetProviders();
                    $location.path('/');
                } else {
                    $scope.errors = response.errors;
                    $scope.errorMessages = response.errorMessages;
                }
            }).error(errorHandler.handleError);
        }
    }])
    .controller('EditProviderCtrl', ['$routeParams', '$scope', '$location', '$http', 'providers', 'restPath', 'errorHandler', 'baseUrl', 'providerTypes', 'data',
        function($routeParams, $scope, $location, $http, providers, restPath, errorHandler, baseUrl, providerTypes, data) {
        var providerId = $routeParams.providerId;

        $scope.baseUrl = baseUrl;
        $scope.sslMismatch = data.sslMismatch;
        $scope.sslDocumentation = data.sslDocumentation;

        providers.getProviders().then(function() {
            $scope.provider = providers.getProviderById(providerId);

            if ($scope.provider == undefined) {
                $location.path('/');
            } else {
                $scope.providerType = _.find(providerTypes, function(pt) { return pt.id == $scope.provider.providerType; });
            }
        });

        $scope.updateProvider = function($event) {
            $event.preventDefault();
            $scope.errors = {};
            $scope.errorMessages = [];

            $http.put(restPath + '/providers/' + providerId, $scope.provider).success(function(response) {
                if (response.errorMessages == undefined && response.errors == undefined) {
                    providers.resetProviders();
                    $location.path('/');
                } else {
                    $scope.errors = response.errors;
                    $scope.errorMessages = response.errorMessages;
                }
            }).error(errorHandler.handleError);
        };
    }])
    .controller('DeleteProviderCtrl', ['$routeParams', '$scope', '$location', '$http', 'providers', 'restPath',
        function($routeParams, $scope, $location, $http, providers, restPath) {
        var providerId = $routeParams.providerId;

        providers.getProviders().then(function() {
            $scope.provider = providers.getProviderById(providerId);

            if ($scope.provider == undefined) {
                $location.path('/');
            }
        });

        $scope.deleteProvider = function() {
            $http['delete'](restPath + '/providers/' + providerId).success(function() {
                providers.resetProviders();
                $location.path('/');
            });
        };
    }]);
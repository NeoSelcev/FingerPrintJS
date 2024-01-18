// ecmascript 5 validator https://jshint.com/

(function ___upf_base(publicObject) {
    try {
        // global configuration
        var config = {
            enabled: true,
            apiKey: "MFl0ZKaCUYzOm0S4nW9z",
            region: "eu",
            site: "https://salmonf.max.co.il",
            fileSource: "<_SITE_>/web/v3/<_KEY_>/iife.min.js",
            timeout: 10000,
            tagName: "_fp_script_library_",
            promiseName: "_fp_script_promise_",
            scriptSourceSitePlaceholder: "<_SITE_>",
            scriptSourceApiKeyPlaceholder: "<_KEY_>",
            storage: {
                type: "sessionStorage"
            },
            fingerPrint: {
                old: {
                    cookieName: "ctFingerPrint"
                },
                new: {
                    enabledMarkName: "max_ufp_enabled",
                    loadMarkName: "max_fp_load",
                    visitorIdMarkName: "max_ufp_value",
                    requestIdMarkName: "max_ufp_req_value",
                    timeStampMarkName: "max_fp_timeStamp",
                    workingMarkName: "max_fp_working"
                }
            },
            terms: {
                alwaysAllowed: false,
                subDomains: ["www", "online", "businessinfo", "businesslc"],
                paths: ["personal", "registred", "registered", "cards/registration/join-wizard", "cards/registration/eligibility-form", "virtualgiftcardprivate/order.aspx", "request-pin-code", "sso-general", "tracker/otp", "general/uploadfiles/login", "anonymous/activatecard.aspx", "auth/recover/enterid", "instant-issuing/bank-access-login", "block-card/questions", "register-website"],
                pathsToExclude: ["registeredtimeout", "login", "/"],
                get domain() {
                    return getRootHostName(document.location.origin);

                    function getRootHostName(url) {
                        var parts = extractDomain(url).split(".");
                        var partsLength = parts.length - 3;
                        for (i = 0; i < partsLength; i++) {
                            parts.shift();
                        }
                        return parts.join(".");
                    }

                    function extractDomain(url) {
                        var domain;
                        if (url.indexOf("://") > -1) {
                            domain = url.split("/")[2];
                        } else {
                            domain = url.split("/")[0];
                        }
                        return domain.split(":")[0];
                    }
                }
            },
            expiration: {
                enabled: false,
                periodInSeconds: {
                    fingerPrint: (10 * 24 * 60 * 60), // 10 days
                    requestId: (10 * 24 * 60 * 60), // 10 days
                },
                fpPeriodInSeconds: (10 * 24 * 60 * 60), // 10 days
                riPeriodInSeconds: (10 * 24 * 60 * 60), // 10 days
            },
            gb: {
                enabled: true,
                eventName: "MAX_EVENT",
                parameterName: "fingerprint"
            },
            log: {
                consoleEnabled: false,
                apiLevelsEnabled: ["warn", "error"], // "debug", "info", "warn", "error"
                chSubdomains: ["www", "online"],
                bsSubdomains: ["businesslc", "businessinfo"],
                get logUrl() {
                    if (config.log.chSubdomains.some(function (subdomain) {
                        return document.location.host.includes(subdomain);
                    })) {
                        return getWholeDomain("www");
                    } else if (config.log.bsSubdomains.some(function (subdomain) {
                        return document.location.host.includes(subdomain);
                    })) {
                        return getWholeDomain("businesslc");
                    } else {
                        return getWholeDomain("www");
                    }

                    function getWholeDomain(subDomain) {
                        return document.location.protocol + "//" + subDomain + "." + config.terms.domain + "/api/logs/log";
                    }
                }
            }
        };

        publicObject.load = function load() {
            try {
                logger.log.info("load started");
                helper.ufpMark = config.enabled;
                if (!config.enabled) {
                    helper.removeValueMarks();
                    return;
                }
                fpLibrary.loadScript();
                logger.log.info("load finished");
            } catch (error) {
                globalStorage.remove(config.fingerPrint.new.loadMarkName);
                logger.log.error("load failed [" + logger.getFullErrorMessage(error) + "]");
            }
        };

        publicObject.run = function run() {
            try {
                logger.log.info("run started");
                helper.ufpMark = config.enabled;
                if (!config.enabled) {
                    helper.removeValueMarks();
                    return;
                }
                if (!helper.fpValueExistsAndValid && helper.fpAllowedToRun && helper.fpLibraryLoaded) {
                    globalStorage.remove(config.fingerPrint.new.loadMarkName);
                    fpLibrary.getFP();
                }
                logger.log.info("run finished");
            } catch (error) {
                logger.log.error("run failed [" + logger.getFullErrorMessage(error) + "]");
            }
        };

        var fpLibrary = {
            working: false,
            loadScript: function loadscript() {
                try {
                    logger.log.debug("loading script");
                    var scriptTag = document.querySelector("#" + config.tagName);
                    if (scriptTag) {
                        logger.log.debug("script already exist");
                        publicObject.run();
                        return;
                    }
                    var script = document.createElement("script");
                    script.id = config.tagName;
                    script.async = true;
                    script.src = config.fileSource.replace(config.scriptSourceSitePlaceholder, config.site).replace(config.scriptSourceApiKeyPlaceholder, config.apiKey);
                    script.onload = function () {
                        logger.log.debug("loading library");
                        if (FingerprintJS && FingerprintJS.load) {
                            var promise = FingerprintJS.load({
                                region: config.region,
                                endpoint: [config.site, FingerprintJS.defaultEndpoint]
                            });
                            localStorage.set(config.promiseName, promise);
                            publicObject.run();
                        } else {
                            logger.log.error("error loading library - FingerprintJS not loaded");
                        }
                    };
                    script.onerror = function () {
                        logger.log.error("script load failed [" + logger.getFullErrorMessage(error) + "]");
                    };
                    document.head.appendChild(script);
                } catch (error) {
                    logger.log.error("exception loading script [" + logger.getFullErrorMessage(error) + "]");
                }
            },
            getFP: function getFP() {
                try {
                    logger.log.info("executing fp api", true);
                    var promise = localStorage.get(config.promiseName);
                    if (promise && promise.then) {
                        if (fpLibrary.working) {
                            logger.log.info("executing fp api - already in process", true);
                            return;
                        }
                        fpLibrary.working = true;
                        promise.then(function (fp) {
                            logger.log.info("executing fp api - call", true);
                            return fp.get({ timeout: config.timeout });
                        }, function(error) {
                            fpLibrary.working = false;
                            logger.log.error("executing fp api - call failed result [" + logger.getFullErrorMessage(error) + "]", true);                            
                        }).then(function (result) {
                            try {
                                logger.log.info("executing fp api - successed", true);
                                logger.log.debug("extracting result [" + JSON.stringify(result) + "]");
                                fpLibrary.working = false;
                                if (result.visitorId && result.requestId) {
                                    globalStorage.set(config.fingerPrint.new.visitorIdMarkName, result.visitorId);
                                    globalStorage.set(config.fingerPrint.new.requestIdMarkName, result.requestId);
                                    globalStorage.set(config.fingerPrint.new.timeStampMarkName, new Date().getTime());
                                    if(config.gb.enabled) {
                                        helper.fireGB(result.visitorId);
                                    }
                                    logger.log.debug("results stored");
                                } else {
                                    fpLibrary.working = false;
                                    logger.log.error("exception extracting result [" + logger.getFullErrorMessage(error) + "]");
                                }
                            } catch (error) {
                                fpLibrary.working = false;
                                logger.log.error("executing fp api - catch failed result [" + logger.getFullErrorMessage(error) + "]", true);
                            }
                        }, function (error) {
                            fpLibrary.working = false;
                            logger.log.error("executing fp api - result failed result [" + logger.getFullErrorMessage(error) + "]", true);
                        });
                    } else {
                        fpLibrary.working = false;
                        logger.log.error("executing fp api failed - library not loaded", true);
                    }

                } catch (error) {
                    fpLibrary.working = false;
                    logger.log.error("exception getting fp [" + logger.getFullErrorMessage(error) + "]");
                }
            }
        };

        var helper = {
            set ufpMark(enabled) {
                var currentMark = globalStorage.get(config.fingerPrint.new.enabledMarkName);
                if (!currentMark || currentMark && currentMark.toLowerCase() !== enabled.toString().toLowerCase()) {
                    globalStorage.set(config.fingerPrint.new.enabledMarkName, enabled);
                }
            },
            get fpValueExistsAndValid() {
                var fpValue = globalStorage.get(config.fingerPrint.new.visitorIdMarkName);
                var requestId = globalStorage.get(config.fingerPrint.new.requestIdMarkName);
                if (fpValue && requestId) {
                    var fpTimeStamp = globalStorage.get(config.fingerPrint.new.timeStampMarkName);
                    if (fpTimeStamp) {
                        if (!config.expiration.enabled) {
                            logger.log.debug("fp exists (expiration validation disabled)");
                            return true;
                        } else if (Math.abs((new Date().getTime() - fpTimeStamp) / 1000) < config.expiration.periodInSeconds.fingerPrint) {
                            logger.log.debug("fp exists (expiration valid)");
                            return true;
                        } else {
                            logger.log.debug("fp exists (expired)");
                        }
                    } else {
                        globalStorage.set(config.fingerPrint.new.timeStampMarkName, new Date().getTime());
                        logger.log.debug("fp exists (expiration stored)");
                        return true;
                    }
                }
                helper.removeValueMarks();
                logger.log.debug("fp removed/does not exists");
                return false;
            },
            get fpAllowedToRun() {
                if (config.terms.alwaysAllowed) {
                    logger.log.debug("allowed (always)");
                    return true;
                }
                var currentHostname = document.location.hostname.toLowerCase();
                var currentPathname = document.location.pathname.toLowerCase();

                var hostnamePattern = "(" + config.terms.subDomains.join("|").toLowerCase() + ")\." + config.terms.domain.replace(".", "\.").toLowerCase();

                var paths = config.terms.paths.join("|").toLowerCase();
                var pathsPattern = paths ? "(\/(" + paths + ")\\b|\\b(" + paths + ")\/)" : "";

                var pathsToExclude = config.terms.pathsToExclude.join("|").toLowerCase();
                var pathsToExcludePattern = pathsToExclude ? "(\/(" + pathsToExclude + ")\\b|\\b(" + pathsToExclude + ")\/)" : "";

                var allowedDomain = new RegExp(hostnamePattern).test(currentHostname);
                var allowedPath = new RegExp(pathsPattern).test(currentPathname);
                var inPathsToExclude = new RegExp(pathsToExcludePattern).test(currentPathname);

                var allowed = allowedDomain && allowedPath && !inPathsToExclude;

                var message = "allowed";
                if (!allowed) {
                    message = "not " + message;
                    if (!allowedDomain) {
                        message += " domain [" + currentHostname + "]";
                    }
                    if (!allowedPath) {
                        message += " path [" + currentPathname + "]";
                    }
                    if (inPathsToExclude) {
                        message += " excluded path [" + currentHostname + "]";
                    }
                }
                logger.log.debug(message);

                return allowed;
            },
            get fpLibraryLoaded() {
                var promise = localStorage.get(config.promiseName);
                return promise ? true : false;
            },
            removeValueMarks: function removeValueMarks() {
                globalStorage.remove(config.fingerPrint.new.visitorIdMarkName);
                globalStorage.remove(config.fingerPrint.new.requestIdMarkName);
                globalStorage.remove(config.fingerPrint.new.timeStampMarkName);
            },
            fireGB: function fireGB(value) {
                logger.log.debug("firing gb");
                try {
                    if(typeof (_detector) !== "undefined" && _detector !== null && _detector !== undefined) {
                        _detector.triggerCustomEvent(config.gb.eventName, config.gb.parameterName + ":" + value, undefined);
                    }
                    logger.log.debug("firing gb successed");
                } catch (error) {
                    logger.log.debug("firing gb failed[" + logger.getFullErrorMessage(error) + "]");
                }                
            }
        };

        // global browser storage (sessionStorage/localStorage) accessible from multiple tabs/windows
        var globalStorage = {
            set: function set(key, value) {
                try {
                    if (globalStorage.enabled) {
                        window[config.storage.type].setItem(key, value);
                    } else {
                        localStorage.set(key, value);
                    }
                } catch (error) {
                    logger.log.warning("storage [" + config.storage.type + " - set] available but not accessible. error [" + logger.getFullErrorMessage(error) + "]");
                    localStorage.set(key, value);
                }
            },
            get: function get(key) {
                try {
                    if (globalStorage.enabled) {
                        return window[config.storage.type].getItem(key);
                    } else {
                        return localStorage.get(key);
                    }
                } catch (error) {
                    logger.log.warning("storage [" + config.storage.type + " - get] available but not accessible. error [" + logger.getFullErrorMessage(error) + "]");
                    return localStorage.get(key);
                }
            },
            remove: function remove(key) {
                try {
                    if (globalStorage.enabled) {
                        window[config.storage.type].removeItem(key);
                    } else {
                        localStorage.remove(key);
                    }
                } catch (error) {
                    logger.log.warning("storage [" + config.storage.type + " - remove] available but not accessible. error [" + logger.getFullErrorMessage(error) + "]");
                    localStorage.remove(key);
                }
            },
            get enabled() {
                var enabled = typeof Storage !== "undefined";
                if (!enabled) {
                    logger.log.warning("storage not available");
                }
                return enabled;
            }
        };

        // local window based storage accessible only in current window/tab
        var localStorage = {
            get: function get(key) {
                try {
                    return window[key];
                } catch (error) {
                    logger.log.error("window [" + key + " - get] is not accessible [" + logger.getFullErrorMessage(error) + "]");
                }

            },
            set: function set(key, value) {
                try {
                    window[key] = value;
                } catch (error) {
                    logger.log.error("window [" + key + " - set] is not accessible [" + logger.getFullErrorMessage(error) + "]");
                }
            },
            remove: function remove(key) {
                try {
                    delete window[key];
                } catch (error) {
                    logger.log.error("window [" + key + " - delete] is not accessible [" + logger.getFullErrorMessage(error) + "]");
                }
            }
        };

        // logger
        var logger = (function () {
            function log(severity, message, force) {
                message = formatMessage(severity, message);
                if (config.log.consoleEnabled) {
                    if (console[severity]) {
                        console[severity](new Date() + ": " + message);
                    } else {
                        console.log(message);
                    }
                }
                if (config.log.apiLevelsEnabled.includes(severity) || force) {
                    sendLog(severity, message);
                }
            }

            function getFullErrorMessage(error) {
                var message = "";
                if (error.name) {
                    message += " name [" + error.name.replace(/(?:\r\n|\r|\n)/g, " ") + "]";
                }
                if (error.message) {
                    message += " message [" + error.message.replace(/(?:\r\n|\r|\n)/g, " ") + "]";
                }
                if (error.stack) {
                    message += " stack [" + error.stack.replace(/(?:\r\n|\r|\n)/g, " ") + "]";
                }
                return message;
            }

            function formatMessage(severity, message) {
                var formattedMessage = "FP [" + severity + "]";
                formattedMessage += ": " + message;
                return formattedMessage;
            }

            function sendLog(severity, message) {
                var xhttp = new XMLHttpRequest();
                xhttp.open("POST", config.log.logUrl);
                xhttp.setRequestHeader("Content-Type", "application/json");
                xhttp.setRequestHeader("ACCEPT", "application/json");
                xhttp.setRequestHeader("URF", document.referrer);
                xhttp.send(JSON.stringify({
                    Message: message,
                    Severity: getSeverity(severity)
                }));

                function getSeverity(severity) {
                    switch (severity) {
                        case "debug":
                            return 4;
                        case "info":
                            return 5;
                        case "warn":
                            return 2;
                        case "error":
                            return 1;
                    }
                }
            }

            return {
                log: {
                    debug: function debug(message) {
                        log("debug", message);
                    },
                    info: function info(message, force) {
                        log("info", message, force);
                    },
                    warning: function warning(message) {
                        log("warn", message);
                    },
                    error: function error(message) {
                        log("error", message);
                    }
                },
                getFullErrorMessage: getFullErrorMessage
            };
        })();
    } catch (error) {
        var message = "Global FP base exception: name [" + error.name.replace(/(?:\r\n|\r|\n)/g, " ") + "] message [" + error.message.replace(/(?:\r\n|\r|\n)/g, " ") + "] stack [" + error.stack.replace(/(?:\r\n|\r|\n)/g, " ") + "]";
        console[console.error ? "error" : "log"](message);
        var xhttp = new XMLHttpRequest();
        xhttp.open("POST", document.location.origin + "/api/logs/log");
        xhttp.setRequestHeader("Content-Type", "application/json");
        xhttp.setRequestHeader("ACCEPT", "application/json");
        xhttp.setRequestHeader("CU", window.location.href);
        xhttp.setRequestHeader("UR", document.referrer);
        xhttp.send(JSON.stringify({
            Message: message,
            Severity: 1
        }));
    }
})(window.___fp = window.___fp || {});
___fp.load();

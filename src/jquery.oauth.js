// Generated by CoffeeScript 1.6.2
(function() {
  (function($) {
    'use strict';
    var Consumer, Request, Token, escape, normalize, parse_form, rfc3986_decode, rfc3986_decode_map, rfc3986_encode, rfc3986_encode_map;

    $.oauth = function(consumer, token, method, url, parameters) {
      var request;

      request = new $.oauth.Request(consumer, token, method, url, parameters);
      return $.ajax({
        type: request.method,
        url: request.url,
        data: request.sign()
      });
    };
    Consumer = (function() {
      function Consumer(key, secret) {
        var data;

        if (key && secret) {
          this.key = key;
          this.secret = secret;
        } else {
          data = parse_form(key);
          this.key = data.oauth_token;
          this.secret = data.oauth_token_secret;
        }
      }

      Consumer.prototype.toString = function() {
        return $.param({
          oauth_token: this.key,
          oauth_token_secret: this.secret
        });
      };

      return Consumer;

    })();
    $.oauth.Consumer = Consumer;
    Token = (function() {
      function Token(key, secret) {
        var data;

        if (key && secret) {
          this.key = key;
          this.secret = secret;
        } else {
          data = parse_form(key);
          this.key = data.oauth_token;
          this.secret = data.oauth_token_secret;
          if (data.oauth_callback_confirmed) {
            this.callback_confirmed = data.oauth_callback_confirmed;
          }
        }
        this.verifier = null;
      }

      Token.prototype.toString = function() {
        return $.param({
          oauth_token: this.key,
          oauth_token_secret: this.secret
        });
      };

      return Token;

    })();
    $.oauth.Token = Token;
    Request = (function() {
      function Request(consumer, token, method, url, parameters) {
        var defaults;

        this.consumer = consumer;
        this.token = token || null;
        this.method = method;
        this.url = url;
        defaults = {
          oauth_consumer_key: this.consumer.key,
          oauth_timestamp: Math.floor(new Date().getTime() / 1000).toString(),
          oauth_nonce: parseInt(Math.random() * 100000000).toString(),
          oauth_version: '1.0',
          oauth_signature_method: 'HMAC-SHA1'
        };
        if (this.token) {
          defaults = $.extend(defaults, {
            oauth_token: this.token.key
          });
          if (this.token.verifier) {
            defaults = $.extend(defaults, {
              oauth_verifier: this.token.verifier
            });
          }
        }
        this.parameters = $.extend({}, defaults, parameters || {});
      }

      Request.prototype.sign = function() {
        var base, key, signature_method;

        base = escape(this.method);
        base += '&' + escape(this.url);
        base += '&' + escape(normalize(this.parameters));
        key = escape(this.consumer.secret) + '&';
        if (this.token) {
          key += escape(this.token.secret);
        }
        signature_method = $.oauth.signature_methods[this.parameters.oauth_signature_method];
        this.signature = signature_method(key, base);
        return $.extend({}, this.parameters, {
          oauth_signature: this.signature
        });
      };

      return Request;

    })();
    $.oauth.Request = Request;
    $.oauth.signature_methods = {
      'HMAC-SHA1': function(key, base) {
        return hmac_sha1(key, base);
      },
      'PLAINTEXT': function(key, base) {
        return key;
      }
    };
    rfc3986_encode_map = {
      '%21': /\!/g,
      '%2A': /\*/g,
      '%27': /\'/g,
      '%28': /\(/g,
      '%29': /\)/g
    };
    rfc3986_decode_map = {
      '!': /%21/g,
      '*': /%2A/g,
      '\'': /%27/g,
      '(': /%28/g,
      ')': /%29/g
    };
    rfc3986_encode = function(value) {
      var re, replacement;

      value = encodeURIComponent(value);
      for (replacement in rfc3986_encode_map) {
        re = rfc3986_encode_map[replacement];
        value = value.replace(re, replacement);
      }
      return value;
    };
    rfc3986_decode = function(value) {
      var re, replacement;

      for (replacement in rfc3986_decode_map) {
        re = rfc3986_decode_map[replacement];
        value = value.replace(re, replacement);
      }
      return decodeURIComponent(value);
    };
    escape = function(value) {
      if (value === void 0) {
        return '';
      }
      return rfc3986_encode(value);
    };
    normalize = function(parameters) {
      var name, names;

      names = (function() {
        var _results;

        _results = [];
        for (name in parameters) {
          _results.push(name);
        }
        return _results;
      })();
      names = names.sort();
      return ((function() {
        var _i, _len, _results;

        _results = [];
        for (_i = 0, _len = names.length; _i < _len; _i++) {
          name = names[_i];
          _results.push(escape(name) + '=' + escape(parameters[name]));
        }
        return _results;
      })()).join('&');
    };
    return parse_form = function(value) {
      var data, pair, _i, _len, _ref;

      data = {};
      if (!value) {
        return data;
      }
      _ref = value.split('&');
      for (_i = 0, _len = _ref.length; _i < _len; _i++) {
        pair = _ref[_i];
        pair = pair.split('=');
        if (pair.length === 2) {
          data[pair[0]] = pair[1];
        }
      }
      return data;
    };
  })(jQuery);

}).call(this);

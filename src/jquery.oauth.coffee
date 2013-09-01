(($) ->
  'use strict'

  $.oauth = (consumer, token, method, url, parameters) ->
    request = new $.oauth.Request(consumer, token, method, url, parameters)
    $.ajax
      type: request.method
      url: request.url
      data: request.sign()

  class Consumer

    constructor: (key, secret) ->
      if key and secret
        @key = key
        @secret = secret
      else
        data = parse_form(key)
        @key = data.oauth_token
        @secret = data.oauth_token_secret

    toString: ->
      $.param
        oauth_token: @key
        oauth_token_secret: @secret

  $.oauth.Consumer = Consumer

  class Token

    constructor: (key, secret) ->
      if key and secret
        @key = key
        @secret = secret
      else
        data = parse_form(key)
        @key = data.oauth_token
        @secret = data.oauth_token_secret
        @callback_confirmed = data.oauth_callback_confirmed if data.oauth_callback_confirmed
      @verifier = null

    toString: ->
      $.param
        oauth_token: @key
        oauth_token_secret: @secret

  $.oauth.Token = Token

  class Request

    constructor: (consumer, token, method, url, parameters) ->
      @consumer = consumer
      @token = token or null
      @method = method
      @url = url

      defaults =
        oauth_consumer_key: @consumer.key
        oauth_timestamp: Math.floor(new Date().getTime() / 1000).toString()
        oauth_nonce: parseInt(Math.random() * 100000000).toString()
        oauth_version: '1.0'
        oauth_signature_method: 'HMAC-SHA1'

      if @token
        defaults = $.extend defaults, oauth_token: @token.key
        defaults = $.extend defaults, oauth_verifier: @token.verifier if @token.verifier

      @parameters = $.extend {}, defaults, parameters or {}

    sign: ->

      # signing base
      base = escape(@method)
      base += '&' + escape(@url)
      base += '&' + escape(normalize(@parameters))

      # signing key
      key = escape(@consumer.secret) + '&'
      key += escape(@token.secret) if @token

      # sign
      signature_method = $.oauth.signature_methods[@parameters.oauth_signature_method]
      @signature = signature_method(key, base)

      return $.extend {}, @parameters,
        oauth_signature: @signature

  $.oauth.Request = Request

  # supported signature methods
  $.oauth.signature_methods =
    'HMAC-SHA1': (key, base) -> hmac_sha1(key, base)
    'PLAINTEXT': (key, base) -> key

  # utilities
  rfc3986_encode_map =
    '/\!/g': '%21'
    '/\*/g': '%2A'
    '/\'/g': '%27'
    '/\(/g': '%28'
    '/\)/g': '%29'

  rfc3986_decode_map =
    '/%21/g': '!'
    '/%2A/g': '*'
    '/%27/g': '\''
    '/%28/g': '('
    '/%29/g': ')'

  rfc3986_encode = (value) ->
    value = encodeURIComponent(value)
    for re, replace of rfc3986_encode_map
      value = value.replace(re, replace) 
    return value

  rfc3986_decode = (value) ->
    for re, replace of rfc3986_decode_map
      value = value.replace(re, replace) 
    return decodeURIComponent(value)

  escape = (value) ->
    return '' if value is undefined
    return rfc3986_encode(value)

  normalize = (parameters) ->
    names = (name for name of parameters)
    names = names.sort()
    return (escape(name) + '=' + escape(parameters[name]) for name in names).join('&')

  parse_form = (value) ->
    data = {}
    return data if not value
    for pair in value.split('&')
      pair = pair.split('=')
      data[pair[0]] = pair[1] if pair.length == 2
    return data

) jQuery

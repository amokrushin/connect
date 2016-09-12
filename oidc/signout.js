/**
 * Module dependencies
 */
var async = require('async')
var authenticator = require('../lib/authenticator')
var settings = require('../boot/settings')
var Client = require('../models/Client')
var IDToken = require('../models/IDToken')

/**
 * Handles signout requests (GETs or POSTs to the /signout endpoint) and ends a
 * user's session. If an ID Token hint and a post-signout URI are provided,
 * verifies that the URI has been pre-registered, signs out, and redirects the
 * user to it. Otherwise, just signs out with no redirect.
 * @method signout
 * @param [req.query.id_token_hint] {String}
 * @param [req.body.id_token_hint] {String} Id Token hint, identifies the
 *   client/user
 * @param [req.query.post_logout_redirect_uri] {String}
 * @param [req.body.post_logout_redirect_uri] {String} If specified, this
 *   handler verifies that the uri was pre-registered, and sends a redirect to
 *   it via an HTTP 303 See Other response.
 * @param [req.query.state] {String}
 * @param [req.body.state] {String} Opaque OIDC state parameter
 */
function signout (req, res, next) {
  var idToken, clientId
  var params = req.query || req.body
  var postLogoutUri = params.post_logout_redirect_uri
  var idHint = params.id_token_hint
  var state = params.state
  var responseSent = false

  if (idHint) {
    idToken = IDToken.decode(idHint, settings.keys.sig.pub)
    if (idToken instanceof Error) return next(idToken)
    clientId = idToken.payload.aud
  }

  async.series([
    // Verify the post-signout uri (must have been registered for this client)
    function (callback) {
      if (!clientId || !postLogoutUri) return callback()
      Client.get(clientId, function (err, client) {
        if (err) return callback(err)
        if (!client) return callback()
        var registeredUris = client.post_logout_redirect_uris
        var isValidUri = registeredUris && ~registeredUris.indexOf(postLogoutUri)
        if (!isValidUri) return callback()
        if (state) {
          postLogoutUri += '?state=' + state
        }
        // sign out and redirect
        authenticator.logout(req)
        res.redirect(303, postLogoutUri)
        responseSent = true
        callback()
      })
    },
    // Otherwise, fall through to default case below
    function (callback) {
      if (responseSent) return callback()
      // Handle all the other cases - no postLogoutUri specified, or the client is
      // unknown, or the given postLogoutUri has not been registered previously.
      // Do not redirect, simply sign out
      authenticator.logout(req)
      res.set({
        'Cache-Control': 'no-store',
        'Pragma': 'no-cache'
      })
      res.sendStatus(204)
      callback()
    }
  ],
  function (err) {
    if (err) return next(err)
  })
}

/**
 * Export
 */
module.exports = signout

module.exports.requireLogin = function requireLogin(auth, options){
  return function requireLoginHandler(req, res, next) {
    var opts = copyOpts(options),
        sess = req.session;
    if(!(sess.user && sess.user.administrator)) {
      opts.locals = {
        login: auth.login_url('/completeLogin')
      };
      res.render('prompt.hbs', opts);
      return;
    }
    next();
  };
};